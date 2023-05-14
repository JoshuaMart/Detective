# frozen_string_literal: true

class Scan
  # AlterX Class : https://github.com/projectdiscovery/Alterx/
  class AlterX
    def self.generate(options, input)
      cmd = "alterx -l #{File.join(options[:result_path], "#{input}.txt")}"
      cmd += " -enrich -o #{File.join(options[:result_path], 'permutations.txt')}"

      Utilities.execute_cmd(cmd)
    end
  end
end
