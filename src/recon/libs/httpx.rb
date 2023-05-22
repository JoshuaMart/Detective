# frozen_string_literal: true

class Scan
  # Httpx Class : https://github.com/projectdiscovery/httpx
  class Httpx
    def self.check(results, options)
      pool = Concurrent::FixedThreadPool.new(5)

      results.each do |_, data|
        data[:vhosts].each do |hostname, _|
          pool.post do
            cmd = "httpx -u '#{hostname}' -silent -p #{httpx_ports(data)} -timeout 10 -td -title -json"
            httpx_results = `#{cmd}`

            httpx_results&.each_line do |result|
              result = JSON.parse(result)

              vhost = extract_infos(result)
              Nuclei.check(vhost, options)

              data[:vhosts][hostname][result['port']] = vhost
            end
          end
        end
      end

      pool.shutdown
      pool.wait_for_termination
    end

    def self.extract_hostnames(options)
      hostnames = []

      cmd = "httpx -l #{File.join(options[:result_path], 'subfinder_puredns_brute_resolved.txt')} -json -silent"
      httpx_results = `#{cmd}`

      httpx_results&.each_line do |result|
        result = JSON.parse(result)

        hostnames << result['input'] unless hostnames.include?(result['input'])
      end

      filename = File.join(options[:result_path], 'httpx_hostnames.txt')
      File.open(filename, 'w+') { |f| f.puts(hostnames) }
    end

    def self.minimize(results)
      results.each do |_, data|
        data[:vhosts].each do |hostname, vhosts|
          data[:vhosts][hostname].delete('80') if vhosts.dig('80', 'location') == vhosts.dig('443', 'url') ||
                                                  vhosts.dig('80', 'hash', 'body_sha256') == vhosts.dig('443', 'hash', 'body_sha256')
        end
      end
    end

    def self.httpx_ports(data)
      ports = []
      data[:ports].each do |port|
        ports << case port
                 when 80
                   'http:80'
                 when 443
                   'https:443'
                 else
                   port
                 end
      end

      ports.join(',')
    end

    def self.extract_infos(result)
      {
        url: normalize_url(result),
        title: result['title'],
        status_code: result['status_code'],
        location: result['location'] || '',
        technologies: result['tech'] || []
      }
    end

    def self.normalize_url(result)
      if result['url'].end_with?(':443')
        result['url'].sub(':443', '')
      elsif result['url'].end_with?(':80')
        result['url'].sub(':80', '')
      else
        result['url']
      end
    end
  end
end
