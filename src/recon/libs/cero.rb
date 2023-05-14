# frozen_string_literal: true

class Scan
  # Cero Class : https://github.com/glebarez/cero
  class Cero
    def self.check(options)
      cmd = "cat #{File.join(options[:result_path], 'to_tls.txt')} | cero -d"
      cero_result = `#{cmd}`

      hostnames = []

      cero_result&.each_line do |result|
        next if result.start_with?('*.') || !result.end_with?(".#{options[:domain]}") || hostnames.include?(result)

        hostnames << result
      end

      filename = File.join(options[:result_path], 'cero.txt')
      File.open(filename, 'w+') { |f| f.puts(hostnames) }
    end
  end
end
