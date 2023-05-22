# frozen_string_literal: true

class Scan
  # Nuclei Class : https://github.com/projectdiscovery/nuclei
  class Nuclei
    def self.check(vhost, options)
      tags = options[:takeover] ? 'tech,takeover' : 'tech'

      cmd = "nuclei -u '#{vhost[:url]}' -tags #{tags} -jsonl -silent -eid tech-detect"
      nuclei_results = `#{cmd}`

      vhost[:nuclei_tech] = []

      nuclei_results&.each_line do |result|
        result = JSON.parse(result)

        if result.dig('info', 'tags')&.include?('tech')
          vhost[:nuclei_tech] << result['template-id'].sub('-detect', '')
        else
          message = "Takeover Detected : #{result['template-id']} - #{result['host']}"
          Utilities.notify(message, options, 'vulns')
        end
      end
    end
  end
end
