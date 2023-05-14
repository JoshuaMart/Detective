# frozen_string_literal: true

class Scan
  # Naabu Class : https://github.com/projectdiscovery/naabu
  class Naabu
    def self.scan(options)
      cmd = "naabu -list #{File.join(options[:result_path], 'all_resolved.txt')} -silent -ec -cdn -json"
      cmd += " -tp #{options[:naabu_top_ports]} -ep #{options[:naabu_ports_exclusions].join(',')}"
      cmd += " -o #{File.join(options[:result_path], 'naabu.json')}"

      Utilities.execute_cmd(cmd)
    end

    def self.normalize(options, results)
      file = File.join(options[:result_path], 'naabu.json')
      File.open(file, 'r').each_line do |line|
        line = JSON.parse(line)

        unless results.key?(line['ip'])
          results[line['ip']] = { cdn: !line['cdn'].nil?, ports: [], vhosts: Concurrent::Hash.new }
        end

        port = line.dig('port', 'Port')
        results[line['ip']][:ports] << port unless results[line['ip']][:ports].include?(port)
        results[line['ip']][:vhosts][line['host']] = {}
      end
    end
  end
end
