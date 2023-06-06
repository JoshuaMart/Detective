# frozen_string_literal: true

class Scan
  # Nuclei Class : https://github.com/projectdiscovery/nuclei
  class Nuclei
    def self.check(vhost, options)
      cmd = "nuclei -u '#{vhost[:url]}' -tags takeover -jsonl -silent"
      nuclei_results = `#{cmd}`

      nuclei_results&.each_line do |result|
        result = JSON.parse(result)

        message = "Takeover Detected : #{result['template-id']} - #{result['host']}"
        Utilities.notify(message, options, 'vulns')
      end
    end
  end
end
