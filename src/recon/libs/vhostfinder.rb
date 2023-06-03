# frozen_string_literal: true

class Scan
  # VHostFinder Class : https://github.com/wdahlenburg/VhostFinder
  class VHostFinder
    def self.check(options, results)
      prepare_vhosts(options)

      results.each do |ip, data|
        cmd = "VhostFinder -ip #{ip} -wordlist #{File.join(options[:result_path], 'possible_vhosts.txt')}"
        vhosts_results = `#{cmd}`
        next if vhosts_results&.empty?

        vhosts_results.split("\n").each do |result|
          next unless result.start_with?('[+]')

          hostname = result.split.last

          cmd = "httpx -u '#{ip}' -H 'Host: #{hostname}' -silent -p https:443 -timeout 10 -td -title -json"
          httpx_result = `#{cmd}`
          next if httpx_result&.empty?

          httpx_result = JSON.parse(httpx_result)

          data[:vhosts][result]['443'] = extract_infos(httpx_result, hostname)
        end
      end
    end

    def self.prepare_vhosts(options)
      cmd = "grep -vxFf #{File.join(options[:result_path], 'subfinder_resolved.txt')}"
      cmd += " #{File.join(options[:result_path], 'subfinder.txt')}"
      cmd += " > #{File.join(options[:result_path], 'possible_vhosts.txt')}"

      Utilities.execute_cmd(cmd)
    end

    def self.extract_infos(result, hostname)
      {
        url: Httpx.normalize_url(result),
        host: hostname,
        title: result['title'],
        status_code: result['status_code'],
        location: result['location'] || '',
        technologies: result['tech'] || []
      }
    end
  end
end
