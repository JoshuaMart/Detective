# frozen_string_literal: true

require 'logger'
require 'colorize'

class Scan
  # Provides helper methods to be used in all the different classes (URL and file manipulation...)
  class Utilities
    # Creates a singleton logger
    def self.logger
      @logger ||= Logger.new($stdout)
    end

    # Set the log level for the previous logger
    def self.log_level=(level)
      logger.level = level.downcase.to_sym
    end

    def self.log_fatal(message)
      logger.fatal(message.red)

      exit
    end

    def self.log_info(message)
      logger.info(message.green)
    end

    def self.log_control(message)
      logger.info(message.light_blue)
    end

    def self.log_warn(message)
      logger.warn(message.yellow)
    end

    def self.execute_cmd(cmd)
      system(cmd, %i[out err] => File::NULL)
    end

    def self.notify(message, options)
      cmd = "echo '#{message}' | notify -silent -pc #{File.join(options[:base_path], 'configs/notify.yaml')}"
      execute_cmd(cmd)
    end
  end
end
