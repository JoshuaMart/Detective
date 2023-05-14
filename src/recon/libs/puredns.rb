# frozen_string_literal: true

class Scan
  # PureDNS Class : https://github.com/d3mondev/puredns
  class PureDNS
    def self.resolve(options, input, output)
      cmd = "puredns resolve #{File.join(options[:result_path], "#{input}.txt")}"
      cmd += " --resolvers #{File.join(options[:wordlist_path], 'resolvers.txt')}"
      cmd += " --resolvers-trusted #{File.join(options[:wordlist_path], 'resolvers-trusted.txt')}"
      cmd += " --write #{File.join(options[:result_path], "#{output}.txt")}"

      Utilities.execute_cmd(cmd)
    end

    def self.bruteforce(options)
      cmd = "puredns bruteforce #{File.join(options[:wordlist_path], 'bruteforce.txt')} #{options[:domain]}"
      cmd += " --resolvers #{File.join(options[:wordlist_path], 'resolvers.txt')}"
      cmd += " --resolvers-trusted #{File.join(options[:wordlist_path], 'resolvers-trusted.txt')}"
      cmd += " --write #{File.join(options[:result_path], 'puredns_brute_resolved.txt')}"

      Utilities.execute_cmd(cmd)
    end
  end
end
