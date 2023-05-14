# frozen_string_literal: true

class Scan
  # Subfinder Class : https://github.com/projectdiscovery/subfinder/
  class Subfinder
    def self.get_domains(options)
      cmd = "subfinder -d #{options[:domain]} -all -silent"
      cmd += " -pc #{File.join(options[:base_path], 'configs/subfinder.yaml')}"
      cmd += " -o #{File.join(options[:result_path], 'subfinder.txt')}"

      Utilities.execute_cmd(cmd)
    end
  end
end
