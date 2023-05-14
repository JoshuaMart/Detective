# frozen_string_literal: true

require 'concurrent'
require 'fileutils'
require 'json'

require_relative 'libs/alterx'
require_relative 'libs/cero'
require_relative 'libs/httpx'
require_relative 'libs/subfinder'
require_relative 'libs/naabu'
require_relative 'libs/puredns'
require_relative 'libs/utilities'
require_relative 'libs/vhostfinder'

# Scan
class Scan
  attr_reader :options
  attr_accessor :results

  def initialize(options)
    @options = options
    @results = Concurrent::Hash.new
  end

  def recon
    Utilities.log_fatal("Provide a domain with '-d' flag") if options[:domain].nil?

    options[:result_path] = File.join('./results', options[:domain])
    FileUtils.mkdir_p(options[:result_path]) unless File.directory?(options[:result_path])

    Utilities.notify("Start recon scan for #{options[:domain]}", options)
    Utilities.log_info('[+] Preparing files for scanning') unless options[:silent]
    prepare_wordlists

    Utilities.log_info('[+] Enumerating subdomains with Subfinder') unless options[:silent]
    Subfinder.get_domains(options)

    Utilities.log_info('[+] Resolve Subfinder domains with PureDNS') unless options[:silent]
    PureDNS.resolve(options, 'subfinder', 'subfinder_resolved')

    Utilities.log_info('[+] Bruteforce domains with PureDNS') unless options[:silent]
    PureDNS.bruteforce(options)

    Utilities.log_info('[+] Combine Subfinder resolved & PureDNS brute results') unless options[:silent]
    cmd = "cat #{File.join(options[:result_path], '*_resolved.txt')}"
    cmd += " | sort -u > #{File.join(options[:result_path], 'subfinder_puredns_brute_resolved.txt')}"
    Utilities.execute_cmd(cmd)

    count = `wc -l #{File.join(options[:result_path], 'subfinder_puredns_brute_resolved.txt')}`.split.first.to_i
    if count <= options[:max_hostnames_permutations]
      Utilities.log_info('[+] Generate AlterX permutations wordlist') unless options[:silent]
      AlterX.generate(options, 'subfinder_puredns_brute_resolved')
    else
      Utilities.log_warn('[+] Too many hostnames to use AlterX, reduce the list by extracting the hostnames reachable via HTTPX') unless options[:silent]
      Httpx.extract_hostnames(options)
      count = `wc -l #{File.join(options[:result_path], 'httpx_hostnames.txt')}`.split.first.to_i
      if count <= options[:max_hostnames_permutations]
        AlterX.generate(options, 'httpx_hostnames')
      else
        Utilities.log_warn('[+] Still too many hostnames to use AlterX, we skip this step') unless options[:silent]
      end
    end

    if File.exist?(File.join(options[:result_path], 'permutations.txt'))
      Utilities.log_info('[+] Resolve permutations with PureDNS') unless options[:silent]
      PureDNS.resolve(options, 'permutations', 'permutations_resolved')
    end

    Utilities.log_info('[+] Combine all resolved results for Cero') unless options[:silent]
    cmd = "cat #{File.join(options[:result_path], '*_resolved.txt')}"
    cmd += " | sort -u > #{File.join(options[:result_path], 'to_cero.txt')}"
    Utilities.execute_cmd(cmd)

    Utilities.log_info('[+] Check domains certificates with Cero') unless options[:silent]
    Cero.check(options)

    Utilities.log_info('[+] Resolve Cero domains with PureDNS') unless options[:silent]
    PureDNS.resolve(options, 'cero', 'cero_resolved')

    Utilities.log_info('[+] Combine all resolved hostnames results') unless options[:silent]
    cmd = "cat #{File.join(options[:result_path], '*_resolved.txt')}"
    cmd += " | sort -u > #{File.join(options[:result_path], 'all_resolved.txt')}"
    Utilities.execute_cmd(cmd)

    Utilities.log_info('[+] Scan ports with Naabu') unless options[:silent]
    Naabu.scan(options)
    Naabu.normalize(options, results)

    Utilities.log_info('[+] Check hostnames with HTTPX') unless options[:silent]
    Httpx.check(results)
    Httpx.minimize(results) if options[:minimize]

    if options[:vhosts]
      Utilities.log_info('[+] Fuzz vHost with vHostFinder') unless options[:silent]
      VHostFinder.check(options, results)
    end

    Utilities.log_info("[+] Recon scan for #{options[:domain]} is finished") unless options[:silent]
    Utilities.notify("Recon scan for #{options[:domain]} is finished", options)

    File.open(File.join(options[:result_path], 'results.json'), 'w') do |f|
      f.write(JSON.pretty_generate(results))
    end
  end

  private

  def prepare_wordlists
    cmd = "wget #{options[:resolvers]} -O #{File.join(options[:wordlist_path], 'resolvers.txt')}"
    Utilities.execute_cmd(cmd)

    cmd = "wget #{options[:resolvers_trusted]} -O #{File.join(options[:wordlist_path], 'resolvers-trusted.txt')}"
    Utilities.execute_cmd(cmd)

    cmd = "wget #{options[:bruteforce]} -O #{File.join(options[:wordlist_path], 'bruteforce.txt')}"
    Utilities.execute_cmd(cmd)
  end
end
