#!/usr/bin/env php
<?php

/* strlen() can be overloaded in mbstring extension, so always using mb_orig_strlen */
if (!function_exists('mb_orig_strlen')) {
    function mb_orig_strlen($str) {
        return strlen($str);
    }
}
if (!function_exists('mb_orig_substr')) {
    function mb_orig_substr($str, $offset, $len = null) {
        return isset($len) ? substr($str, $offset, $len) : substr($str, $offset);
    }
}
if (!function_exists('mb_orig_strpos')) {
    function mb_orig_strpos($haystack, $needle, $offset = 0) {
        return strpos($haystack, $needle, $offset);
    }
}

$unrealsync = new Unrealsync();
try {
    $unrealsync->init($_SERVER['argv']);
    $unrealsync->run();
} catch (UnrealsyncException $e) {
    UnrealsyncLogger::exception($e);
    exit(1);
}

class UnrealsyncException extends Exception {}
class UnrealsyncIOException extends UnrealsyncException {}
class UnrealsyncFileException extends UnrealsyncException {}

class Unrealsync
{
    const OS_BSD = 'freebsd';
    const OS_WIN = 'windows';
    const OS_MAC = 'darwin';
    const OS_LIN = 'linux';

    const REPO = '.unrealsync';
    const REPO_CLIENT_CONFIG = '.unrealsync/client_config';
    const REPO_SERVER_CONFIG = '.unrealsync/server_config';
    const REPO_FILES = '.unrealsync/files';
    const REPO_TMP = '.unrealsync/tmp';
    const REPO_LOCK = '.unrealsync/lock';
    const REPO_PID = '.unrealsync/pid';
    const REPO_WATCHER_PID = '.unrealsync/watcher_pid';
    const REPO_KILL_FILE = '.unrealsync/shutdown';

    /* Remote commands (length not more than 10 symbols) */
    const CMD_SHUTDOWN = 'shutdown';
    const CMD_PING = 'ping';
    const CMD_APPLY_DIFF = "applydiff";
    const CMD_BIG_INIT = "biginit";
    const CMD_CHUNK_RCV = "chunkrcv";
    const CMD_BIG_COMMIT = "bigcommit";
    const CMD_BIG_ABORT = "bigabort";

    /* diff answers */
    const EMPTY_LOCAL  = "local\n";
    const EMPTY_REPO   = "repo\n";
    const EMPTY_HEADER = "EMPTY:";

    const MAX_MEMORY = 16777216; // max 16 Mb per read
    const MAX_CONFLICTS = 20;

    const CONTENT_HEADER_LENGTH = 10;
    const SEPARATOR = "\n------------\n"; // separator for diff records

    const SYNC_FROM_LOCAL = "local";
    const SYNC_FROM_REMOTE = "remote";

    /** @var UnrealsyncLogger */
    private $logger;
    /** @var UnrealsyncSsh */
    private $ssh;

    private $is_unix = false, $is_server = false, $is_debug = false, $finished = false, $had_changes = false;

    private $os, $user = 'user';

    private $onsync = false; // command executed upon successul sync

    private $lockfp = null;

    private $diff = ""; // current diff
    private $chunk_filename = "", $chunk_tmp_filename = "", $chunk_fp;

    /* options from config */
    private $servers = array();

    private $watcher = array(
        'pp'   => null, // proc_open handle
        'pipe' => null, // stdout pipe
    );

    private $remotes = array(
        // srv => array(pp => ..., read_pipe => ..., write_pipe => ...)
    );

    /* default ignores */
    private $exclude = array(
        '.' => true, '..' => true, '.unrealsync' => true
    );

    function stopIfNotUnrealsyncdir($exit = true) {
        if (!is_dir('.unrealsync')) {
            if (!$exit) return false;
            echo "Directory .unrealsync not found\n";
            exit(1);
        }
        return true;
    }

    function getPidAndName($pid_file, $process_name) {
        if (!file_exists($pid_file)) return array(null, null);
        $pid = file_get_contents($pid_file);
        $pid_name = `ps o pid,command $pid | grep $process_name`;
        return array($pid, $pid_name);
    }

    public function init($argv)
    {
        $me = array_shift($argv);
        $log_level = UnrealsyncLogger::LOG_INFO;
        $bootstrap = null;
        $sync = null;
        foreach ($argv as $k => $v) {
            if ($v == 'stop') {
                $this->stopIfNotUnrealsyncdir();
                touch(self::REPO_KILL_FILE);
                sleep(1);
                list ($pid, $pid_name) = $this->getPidAndName(self::REPO_PID, 'unrealsync');
                if (empty($pid_name)) exit(0);
                echo "Still running at $pid\n";
                `kill $pid`;
                list ($watcher_pid, $watcher_pid_name) = $this->getPidAndName(self::REPO_WATCHER_PID, 'notify');
                if (!empty($watcher_pid_name)) `kill $watcher_pid`;
                exit();
            } else if ($v === 'status') {
                $this->stopIfNotUnrealsyncdir();
                list ($pid, $pid_name) = $this->getPidAndName(self::REPO_PID, 'unrealsync');
                echo $pid_name . "\n";
                exit();
            } else if ($v === 'config') {
                $wizard = new UnrealsyncWizard();
                $wizard->configCommand($argv);
                exit(0);
            } else if ($v === '--server') {
                $this->is_server = true;
            } else if ($v === '--debug') {
                $log_level = UnrealsyncLogger::LOG_DEBUG;
                $this->is_debug = true;
            } else if (substr($v, 0, 12) == '--bootstrap=') {
                $bootstrap = substr($v, 12);
                break;
            } else if (substr($v, 0, 7) == '--sync=') {
                $sync = substr($v, 7);
                break;
            } else {
                continue;
            }
            unset($argv[$k]);
        }

        $is_repo_setup = $this->stopIfNotUnrealsyncdir(false);
        if (!$is_repo_setup && !$this->is_server) {
            $wizard = new UnrealsyncWizard();
            if (!$wizard->configWizard()) exit(0);
        } else if (!$bootstrap && !$sync && !$this->is_server) {
            list ($pid, $pid_name) = $this->getPidAndName(self::REPO_PID, 'unrealsync');
            if ($pid_name) {
                echo "Already running at $pid\n";
                exit(1);
            }
        }

        if (getenv('UNREALSYNC_DEBUG')) {
            $this->is_debug = true;
            $log_level = UnrealsyncLogger::LOG_DEBUG;
        }

        $this->logger = new UnrealsyncLogger($log_level);
        $this->ssh = new UnrealsyncSsh($this->logger);

        if ($argv && !$bootstrap && !$sync) {
            $this->logger->info('Unrecognized parameters: ' . implode(', ', $argv));
            $this->logger->info('Usage: ' . $me . '[--server] [--debug]');
            exit(1);
        }

        $this->_setupPHP();
        $this->_setupOS();
        if (!$this->_setupUnrealsyncDir()) throw new UnrealsyncException('Could not setup repo');
        if (!$this->is_server) $this->_setupSettings();
        if ($bootstrap) {
            $this->finished = true;
            $this->_bootstrap($bootstrap);
            exit(0);
        } else if ($sync) {
            $this->finished = true;
            $this->_sync($sync, self::SYNC_FROM_LOCAL);
            exit(0);
        }
    }

    public function __destruct()
    {
        $this->finish();
    }

    public function finish()
    {
        if ($this->finished) return;
        if ($this->logger) $this->logger->info('Shutting down on script end');
        $this->finished = true;
        if ($this->watcher['pp']) {
            proc_terminate($this->watcher['pp']);
            proc_close($this->watcher['pp']);
        }

        foreach ($this->remotes as $srv => $remote) {
            if ($remote) {
                try {
                    $this->_remoteExecute($srv, self::CMD_SHUTDOWN);
                } catch (Exception $e) {}
            }
        }
    }

    /* PHP must write all errors to STDERR as otherwise it will interfere with our communication protocol that uses STDOUT */
    private function _setupPHP()
    {
        error_reporting(E_ALL | E_STRICT);
        ini_set('display_errors', 0);
        ini_set('log_errors', 1);
        ini_set('error_log', null);
    }

    private function _setupOS()
    {
        if (PHP_OS == 'WINNT') {
            $this->os = self::OS_WIN;
            return;
        }

        $this->is_unix = true;
        if (PHP_OS == 'FreeBSD') $this->os = self::OS_BSD;
        else if (PHP_OS == 'Darwin') $this->os = self::OS_MAC;
        else if (PHP_OS == 'Linux') $this->os = self::OS_LIN;
        else throw new UnrealsyncException("Unsupported client OS: " . PHP_OS);

        if (isset($_SERVER['USER'])) $this->user = $_SERVER['USER'];
    }

    private function _setupUnrealsyncDir()
    {
        if ($this->is_server) chdir(dirname(__FILE__));
        if (!is_dir(self::REPO)) {
            $old_cwd = getcwd();
            while (realpath('..') != realpath(getcwd())) {
                if (!chdir('..')) break;
                if (is_dir(self::REPO)) break;
            }

            if (!is_dir(self::REPO)) {
                chdir($old_cwd);
                return false;
            }
        }

        if (!is_dir(self::REPO_TMP) && !mkdir(self::REPO_TMP)) {
            throw new UnrealsyncException("Cannot create directory " . self::REPO_TMP);
        }
        if (!is_dir(self::REPO_FILES) && !mkdir(self::REPO_FILES)) {
            throw new UnrealsyncException("Cannot create directory " . self::REPO_FILES);
        }
        if (file_exists(self::REPO_KILL_FILE) && !unlink(self::REPO_KILL_FILE)) {
            throw new UnrealsyncException("Cannot remove kill file " . self::REPO_KILL_FILE);
        }
        return true;
    }

    private function _lock()
    {
        $this->lockfp = fopen(self::REPO_LOCK, 'a');
        if (!$this->lockfp) throw new UnrealsyncException("Cannot open " . self::REPO_LOCK);
        if (defined('LOCK_NB')) {
            if (!flock($this->lockfp, LOCK_EX | LOCK_NB, $wouldblock)) {
                if ($wouldblock) {
                    throw new UnrealsyncException("Another instance of unrealsync already running for this repo");
                } else {
                    throw new UnrealsyncException("Cannot do flock() for " . self::REPO_LOCK);
                }
            }
        } else {
            $this->logger->info('Trying to obtain lock for ' . self::REPO_LOCK);
            if (!flock($this->lockfp, LOCK_EX)) throw new UnrealsyncException("Cannot do flock for " . self::REPO_LOCK);
        }
    }

    private function _setupSettings()
    {
        list($servers, $exclude, $onsync) = self::_loadConfig();
        $this->exclude = array_merge($this->exclude, $exclude);
        $this->servers = $servers;
        $this->onsync = $onsync;
    }

    public static function _loadConfig()
    {
        $file = self::REPO_CLIENT_CONFIG;
        $config = parse_ini_file($file, true);
        if ($config === false) throw new UnrealsyncException("Cannot parse ini file $file");
        if (!isset($config['general_settings'])) throw new UnrealsyncException("Section [general_settings] not found in $file");
        $core_settings = $config['general_settings'];
        unset($config['general_settings']);
        $exclude = array();
        if (isset($core_settings['exclude'])) {
            foreach ($core_settings['exclude'] as $excl) {
                $exclude[$excl] = true;
            }
        }

        $onsync = !empty($core_settings['onsync']) ? $core_settings['onsync'] : null;
        foreach ($config as $host => &$settings) {
            if (isset($settings['disable'])) unset($config[$host]);
            if (!isset($settings['host'])) $settings['host'] = $host;
            if (!isset($settings['php']) && isset($core_settings['php'])) $settings['php'] = $core_settings['php'];
            if (!isset($settings['dir']) && isset($core_settings['dir'])) $settings['dir'] = $core_settings['dir'];
            if (!isset($settings['os']) && isset($core_settings['os'])) $settings['os'] = $core_settings['os'];
        }

        if (!count($config)) throw new UnrealsyncException("No server sections in $file");
        return array($config, $exclude, $onsync);
    }

    private function _startLocalWatcher()
    {
        $binary = ($this->os == self::OS_WIN ? '' : 'exec ') . __DIR__ . '/bin/' . $this->os . '/notify ';
        if ($this->os == self::OS_LIN || $this->os == self::OS_MAC) {
            $binary .= '.';
        } else if ($this->os == self::OS_WIN) {
            $binary .= '.';
        } else {
            throw new UnrealsyncException("Start local watcher for $this->os is not yet implemented, sorry");
        }
        $pp = proc_open($binary, array(array('file', $this->os == self::OS_WIN ? 'nul' : '/dev/null', 'r'), array('pipe', 'w'), STDERR), $pipes);
        if (!$pp) throw new UnrealsyncException("Cannot start local watcher ($binary)");
        //TODO remove this after notifier could exit by itself
        $status = proc_get_status($pp);
        file_put_contents(self::REPO_WATCHER_PID, $status['pid']);

        $this->watcher = array(
            'pp' => $pp,
            'pipe' => $pipes[1],
        );
    }

    private function _fullRead($fp, $len, $srv = null)
    {
        if ($len <= 0) return '';
        if ($len > self::MAX_MEMORY) {
            throw new UnrealsyncException("Going to read from socket over memory limit ($len bytes)");
        }
        if (!$srv) $srv = $_ENV['SSH_CLIENT'];
        $buf = '';
        $chunk_size = 65536;

        $read = array($fp);
        $write = $except = null;
        while (stream_select($read, $write, $except, null)) {
            $result = fread($fp, min($chunk_size, $len - mb_orig_strlen($buf)));
            $this->logger->debug("Read result from $srv: " . var_export($result, true));
            if ($result === false || !mb_orig_strlen($result)) throw new UnrealsyncIOException("Cannot read from $srv");

            $buf .= $result;
            if (mb_orig_strlen($buf) >= $len) break;
            $read = array($fp);
        }

        return $buf;
    }

    private function _fullWrite($fp, $str, $srv = null)
    {
        if (!mb_orig_strlen($str)) return;
        $bytes_sent = 0;
        $chunk_size = 65536;
        $write = array($fp);
        $read = $except = null;
        while (stream_select($read, $write, $except, null)) {
            $chunk = mb_orig_substr($str, $bytes_sent, $chunk_size);
            $this->logger->debug("Writing to $srv: $chunk");
            $result = fwrite($fp, $chunk);
            $this->logger->debug("Write result from $srv: " . var_export($result, true));

            if ($result === false || $result === 0) {
                throw new UnrealsyncIOException("Cannot write to $srv");
            }

            $bytes_sent += $result;
            if ($bytes_sent >= mb_orig_strlen($str)) return;
            $write = array($fp);
        }
    }

    private function _remoteExecuteAll($cmd, $data = null)
    {
        foreach ($this->remotes as $srv => $_) $this->_remoteExecute($srv, $cmd, $data);
    }

    private function _remoteExecute($srv, $cmd, $data = null)
    {
        if (!$this->remotes[$srv]) throw new UnrealsyncException("Incorrect remote server $srv");
        $write_pipe = $this->remotes[$srv]['write_pipe'];
        $read_pipe = $this->remotes[$srv]['read_pipe'];

        $this->logger->_timerStart();
        $this->_fullWrite($write_pipe, sprintf("%10s%10u%s", $cmd, mb_orig_strlen($data), $data), $srv);
        $len = $this->_fullRead($read_pipe, self::CONTENT_HEADER_LENGTH, $srv);
        $len = intval($len);
        $this->logger->_timerStop("$srv: exec $cmd");
        $this->logger->_timerStart();
        $result = $this->_fullRead($read_pipe, $len, $srv);
        $this->logger->_timerStop("$srv: recv $cmd");
        return $result;
    }

    private function _bootstrap($srv)
    {
        $data = $this->servers[$srv];
        if (!$data) throw new UnrealsyncException("Internal error: no data for server $srv");
        if (!$host = $data['host']) throw new UnrealsyncException("No 'host' entry for $srv");
        if (!$dir  = $data['dir']) throw new UnrealsyncException("No 'dir' entry for $srv");
        $repo_dir = rtrim($dir, '/') . '/' . self::REPO;
        if (empty($data['os'])) {
            $this->logger->info('Retrieving OS because it was not specified in config');
            $data['os'] = self::ssh($host, "uname", $data);
            if ($data['os'] === false) throw new UnrealsyncException("Cannot get uname for '$srv");
        }
        $data['os'] = ucfirst(strtolower($data['os']));
        if (!in_array($data['os'], array('Linux', 'Darwin', 'Freebsd'))) throw new UnrealsyncException("Unsupported remote os '$data[os]' for $srv");

        $this->logger->info("Checking files on $srv");
        $watcher_path = __DIR__ . '/bin/' . strtolower($data['os']) . '/notify';
        $php_bin = (!empty($data['php']) ? $data['php'] : 'php');
        $dir_esc = escapeshellarg($repo_dir);
        $cmd = "if [ ! -d $dir_esc ]; then mkdir $dir_esc; fi; ";
        $remote_files = array(__FILE__, $watcher_path);
        foreach ($remote_files as $k => $f) {
            $rf = escapeshellarg("$repo_dir/" . basename($f));
            $cmd .= "if [ -f $rf ]; then $php_bin -r 'echo \"$k=\" . md5_file(\"'$rf'\") . \"\\n\";'; fi;";
        }
        $result = $this->ssh->ssh($host, $cmd, $data);
        $lines = explode("\n", $result);
        foreach ($lines as $ln) {
            if (!$ln) continue;
            list($idx, $rest) = explode("=", $ln, 2);
            $local_md5 = md5_file($remote_files[$idx]);
            if (!preg_match('/[a-f0-9]{32}/s', $rest, $m)) continue;
            if ($local_md5 === $m[0]) unset($remote_files[$idx]);
        }
        if (!empty($remote_files)) {
            $this->logger->info('Copying files');
            foreach ($remote_files as $f) {
                $result = $this->ssh->scp($host, $f, $repo_dir . '/', $data);
                if ($result === false) throw new UnrealsyncException("Cannot scp $f to $srv");
            }
        }
    }

    public function startServer($srv) {
        $data = $this->servers[$srv];
        if (!$data) throw new UnrealsyncException("Internal error: no data for server $srv");
        if (!$host = $data['host']) throw new UnrealsyncException("No 'host' entry for $srv");
        if (!$dir  = $data['dir']) throw new UnrealsyncException("No 'dir' entry for $srv");
        $repo_dir = rtrim($dir, '/') . '/' . self::REPO;

        $this->logger->info("Starting unrealsync server on $srv");

        $data = $this->servers[$srv];
        if (!$host = $data['host']) throw new UnrealsyncException("No 'host' entry for $srv");
        $php_bin = (!empty($data['php']) ? $data['php'] : 'php');
        if ($this->is_debug) $php_bin = "export UNREALSYNC_DEBUG=1; $php_bin";

        $result = $this->ssh->ssh(
            $host,
            $php_bin . " " . escapeshellarg($repo_dir . '/' . basename(__FILE__)) . " --server",
            $data + array('proc_open' => true)
        );
        if ($result === false) throw new UnrealsyncException("Cannot start unrealsync daemon on $srv");

        $this->remotes[$srv] = $result;
        if (($res = $this->_remoteExecute($srv, self::CMD_PING)) != "pong") {
            throw new UnrealsyncException("Ping failed. Something went wrong: " . var_export($res, true));
        }
    }

    private function _directSystem($cmd, $return = false)
    {
        $this->logger->debug($cmd);
        $proc = proc_open($cmd, array(STDIN, STDOUT, STDERR), $pipes);
        if ($return) return $proc;
        if (!$proc) return 255;
        return proc_close($proc);
    }

    private function _sync($srv, $sync_direction = null)
    {
        $ssh_port = isset($this->servers[$srv]['port']) ? ' -p' . $this->servers[$srv]['port'] : '';
        $rsync_ssh = "-e \"ssh -o ControlMaster=no -o ControlPath=/nonexistent\" $ssh_port";
        $rsync_cmd = "rsync -v -a --delete --exclude=" . self::REPO . " $rsync_ssh";
        $username = isset($this->servers[$srv]['username']) ? $this->servers[$srv]['username'] . '@' : '';
        $remote_arg = escapeshellarg($username . $this->servers[$srv]['host'] . ":" . rtrim($this->servers[$srv]['dir'], "/") . "/");
        switch ($sync_direction) {
            case self::SYNC_FROM_LOCAL:
                $this->logger->info('Rsync to ' . $srv);
                $cmd = "$rsync_cmd ./ $remote_arg";
                $this->_exec($cmd, $out, $retval);
                if ($retval) throw new UnrealsyncException("Cannot do '$cmd'");
                break;
            case self::SYNC_FROM_REMOTE:
                $this->logger->info('Rsync from ' . $srv);
                $cmd = "$rsync_cmd $remote_arg ./";
                $this->_exec($cmd, $out, $retval);
                if ($retval) throw new UnrealsyncException("Cannot do '$cmd'");
                break;
            default:
                throw new UnrealsyncException("Unknown sync direction: $sync_direction");
        }
        $this->logger->info('Rsync done ' . $srv);

        return true;
    }

    private function _exec($cmd, &$out, &$retval)
    {
        $this->logger->debug($cmd);
        return exec($cmd, $out, $retval);
    }

    /*
     * Write file $filename with $stat and $contents to work copy
     * If $commit = true, then repository is updated as well
     */
    private function _writeFile($filename, $stat, $contents, $commit = false)
    {
        $old_stat = $this->_stat($filename);
        if ($stat === "dir") {
            if ($old_stat === "dir") return true;
            $this->_removeRecursive($filename);
            if (!mkdir($filename, 0777, true)) throw new UnrealsyncException("Cannot create dir $filename");
        } else if (strpos($stat, "symlink=") === 0) {
            if (strpos($old_stat, "symlink=") !== 0) $this->_removeRecursive($filename);
            list(, $lnk) = explode("=", $stat, 2);
            if (!symlink($lnk, $filename)) {
                throw new UnrealsyncException("Cannot create symlink $filename");
            }
        } else {
            if ($this->is_unix) {
                if (!is_dir(dirname($filename))) mkdir(dirname($filename), 0777, true);
                $tmp = self::REPO_TMP . "/" . basename($filename);
                $bytes_written = file_put_contents($tmp, $contents);
                if ($bytes_written === false || $bytes_written != mb_orig_strlen($contents)) {
                    throw new UnrealsyncException("Cannot write contents to $tmp");
                }
                foreach (explode("\n", $stat) as $ln) {
                    list($field, $value) = explode("=", $ln);
                    if ($field === "mode" && !chmod($tmp, $value)) {
                        throw new UnrealsyncException("Cannot chmod $filename");
                    } else if ($field === "mtime" && !touch($tmp, $value)) {
                        throw new UnrealsyncException("Cannot set mtime for $filename");
                    }
                }
                if (!rename($tmp, $filename)) {
                    $this->logger->info("Cannot rename $tmp to $filename");
                    return false;
                }
            }
        }

        return $commit ? $this->_commit($filename, $stat) : true;
    }

    /*
     * Update repository entry for $filename
     */
    private function _commit($filename, $stat = null)
    {
        if ($filename === "." || !$filename) return true;

        if (!$stat) $stat = $this->_stat($filename);
        $repof = self::REPO_FILES . "/$filename";
        $rstat = $this->_rstat($filename);

        if ($stat === "dir") {
            if ($rstat && $rstat !== "dir" && !unlink($repof)) throw new UnrealsyncException("Cannot remove $repof");
            if ($rstat !== "dir" && !mkdir($repof, 0777, true)) throw new UnrealsyncException("Cannot create dir $repof");
            return true;
        }

        if ($rstat === "dir") $this->_removeRecursive($repof);
        if (!is_dir(dirname($repof))) mkdir(dirname($repof), 0777, true);

        $tmp = self::REPO_TMP . "/" . basename($filename);
        $bytes_written = file_put_contents($tmp, $stat);
        if ($bytes_written === false || $bytes_written != mb_orig_strlen($stat)) {
            throw new UnrealsyncException("Cannot write contents to $tmp");
        }
        if (!rename($tmp, $repof)) {
            $this->logger->info("Cannot rename $tmp to $repof");
            return false;
        }
        return true;
    }


    private function _appendContents($file, $stat)
    {
        if (mb_orig_strpos($stat, "symlink=") !== false) return;
        $contents = file_get_contents($file);
        if ($contents === false) throw new UnrealsyncFileException("Cannot read $file");
        $size = $this->_getSizeFromStat($stat);
        if (mb_orig_strlen($contents) != $size) throw new UnrealsyncFileException("Actual file size does not match stat");
        $this->diff .= sprintf("%10u", $size);
        $this->diff .= $contents;
    }

    /* Prevent from having too big diff that exceeds MAX_MEMORY
       If TRUE is returned then file is very big and it's processing must be skipped
    */
    private function _optimizeSendBuffers($diff_str, $file, $stat)
    {
        if (!mb_orig_strlen($stat)) $sz = 0;
        else $sz = $this->_getSizeFromStat($stat) + self::CONTENT_HEADER_LENGTH;

        if (mb_orig_strlen($diff_str) + $sz >= self::MAX_MEMORY) {
            $this->_sendBigFile($file);
            return true;
        } else if (mb_orig_strlen($diff_str) + mb_orig_strlen($this->diff) + $sz >= self::MAX_MEMORY) {
            $this->_sendAndCommitDiff();
        }
        return false;
    }

    private function _cmdBigInit($filename)
    {
        $this->chunk_filename = $filename;
        $this->chunk_tmp_filename = self::REPO_TMP . "/" . basename($filename);
        $this->chunk_fp = fopen($this->chunk_tmp_filename, "w");
        if (!$this->chunk_fp) throw new UnrealsyncException("Cannot open temporary file for chunk");
        return true;
    }

    private function _cmdChunkRcv($chunk)
    {
        if (fwrite($this->chunk_fp, $chunk) !== mb_orig_strlen($chunk)) {
            throw new UnrealsyncException("Could not write chunk");
        }

        return true;
    }

    private function _cmdBigCommit($stat)
    {
        if (!fclose($this->chunk_fp)) {
            throw new UnrealsyncException("Could not fclose() chunk file pointer");
        }
        if (!rename($this->chunk_tmp_filename, $this->chunk_filename)) {
            throw new UnrealsyncException("Could not move $this->chunk_filename");
        }
        if (!$this->_commit($this->chunk_filename, $stat)) {
            throw new UnrealsyncException("Could not commit $this->chunk_filename");
        }

        return true;
    }

    private function _cmdBigAbort()
    {
        if (!fclose($this->chunk_fp)) {
            throw new UnrealsyncException("Could not fclose() chunk file pointer");
        }
        if (!unlink($this->chunk_tmp_filename)) {
            throw new UnrealsyncException("Could not unlink $this->chunk_filename");
        }
        return true;
    }

    private function _sendBigFile($file)
    {
        $stat = $this->_stat($file);
        if (!$stat) throw new UnrealsyncFileException("File vanished: $file");
        $rstat = $this->_rstat($file);
        if ($stat === $rstat) return;

        $sz = $this->_getSizeFromStat($stat);
        if (!$sz) throw new UnrealsyncException("Internal error: no size for big file");

        $fp = fopen($file, "rb");
        if (!$fp) throw new UnrealsyncFileException("Could not open big file $file for reading");
        $this->logger->info("Sending big file $file (" . round($sz / 1024) . " KiB)");

        $this->_remoteExecuteAll(self::CMD_BIG_INIT, $file);
        while (mb_orig_strlen($chunk = fread($fp, self::MAX_MEMORY / 2))) {
            if ($stat !== $this->_stat($file)) {
                $this->logger->info('Big file changed, aborting');
                $this->_remoteExecuteAll(self::CMD_BIG_ABORT);
                fclose($fp);
                return;
            }
            $this->_remoteExecuteAll(self::CMD_CHUNK_RCV, $chunk);
        }

        fclose($fp);
        $this->_remoteExecuteAll(self::CMD_BIG_COMMIT, $stat);
        $this->_commit($file, $stat);

        $this->logger->info("Big file $file sent (" . round($sz / 1024) . " KiB)");
    }

    private function _appendDiff($dir, $recursive = true)
    {
        // if we cannot open directory, it means that it vanished during diff computation. It is actually acceptable
        @$dh = opendir($dir);
        if (!$dh) throw new UnrealsyncFileException("Cannot opendir($dir)");
        try {
            $files = array();
            while (false !== ($rel_path = readdir($dh))) {
                if (isset($this->exclude[$rel_path])) continue;
                $file = "$dir/$rel_path";
                $stat = $this->_stat($file);
                if (!$stat) throw new UnrealsyncFileException("File vanished: $file");

                $files[$file] = true;
                $rstat = $this->_rstat($file);

                if (!$rstat) {
                    if ($stat === "dir") {
                        $this->_appendAddedFiles($file);
                    } else {
                        $str = "A $file\n$stat" . self::SEPARATOR;
                        if ($this->_optimizeSendBuffers($str, $file, $stat)) continue;
                        $this->diff .= $str;
                        $this->_appendContents($file, $stat);
                    }
                    continue;
                }

                if ($stat === $rstat) {
                    if ($stat === "dir" && $recursive) $this->_appendDiff($file, $recursive);
                    continue;
                }

                $str = "M $file\n$rstat\n\n$stat" . self::SEPARATOR;
                if ($this->_optimizeSendBuffers($str, $file, $stat)) continue;
                $this->diff .= $str;
                $this->_appendContents($file, $stat);
            }
        } catch (Exception $e) {
            closedir($dh);
            throw $e;
        }

        closedir($dh);

        // determine deletions by looking up files that are present in repository but not on disk
        // It is ok if we do not yet have any repository entry for directory because it needs to be commited first
        @$dh = opendir(self::REPO_FILES . "/$dir");
        if ($dh) {
            while (false !== ($rel_path = readdir($dh))) {
                if ($rel_path === "." || $rel_path === "..") continue;
                $file = "$dir/$rel_path";
                if (mb_orig_strlen($this->_stat($file)) > 0) continue;
                $rstat = $this->_rstat($file);
                $str = "D $file\n$rstat" . self::SEPARATOR;
                $this->_optimizeSendBuffers($str, $file, "");
                $this->diff .= $str;
            }
            closedir($dh);
        }
    }

    private function _appendAddedFiles($dir)
    {
        @$dh = opendir($dir);
        if (!$dh) {
            $this->logger->debug("_appendAddedFiles: cannot opendir($dir)");
            return;
        }

        $str = "A $dir\ndir" . self::SEPARATOR;
        $this->_optimizeSendBuffers($str, $dir, "");
        $this->diff .= $str;

        while (false !== ($rel_path = readdir($dh))) {
            if (isset($this->exclude[$rel_path])) continue;
            $file = "$dir/$rel_path";
            $stat = $this->_stat($file);
            if (!$stat) {
                $this->logger->debug("Cannot compute lstat for $file");
                continue;
            }

            if ($stat === "dir") {
                $this->_appendAddedFiles($file);
            } else {
                $str = "A $file\n$stat" . self::SEPARATOR;
                if ($this->_optimizeSendBuffers($str, $file, $stat)) continue;
                $this->diff .= $str;
                $this->_appendContents($file, $stat);
            }
        }
        closedir($dh);
    }

    private function _cmdPing()
    {
        return "pong";
    }

    private function _getSizeFromStat($stat)
    {
        if (mb_orig_strpos($stat, "symlink=") !== false) return 0;

        $offset = mb_orig_strpos($stat, "size=") + 5;
        return mb_orig_substr($stat, $offset, mb_orig_strpos($stat, "\n", $offset) - $offset);
    }

    /* get file stat that we have in repository (if any) */
    private function _rstat($short_filename)
    {
        clearstatcache();
        $filename = self::REPO_FILES . "/$short_filename";
        if (!file_exists($filename)) return "";
        if (is_dir($filename)) return "dir";
        return file_get_contents($filename);
    }

    /* get file stat, that is used to compare local and remote files */
    private function _stat($filename)
    {
        clearstatcache();
        $result = @lstat($filename);
        if ($result === false) return '';
        switch ($result['mode'] & 0170000) {
            case 0040000:
                return "dir";
            case 0120000:
                return "symlink=" . readlink($filename);
            case 0100000: // regular file
                $mode = $result['mode'] & 0777;
                return sprintf("mode=%d\nsize=%d\nmtime=%d", $mode, $result['size'], $result['mtime']);
        }
        return '';
    }

    /*
     * Commit whole directory, recursively by default
     */
    private function _commitDir($dir = ".", $recursive = true)
    {
        $dh = opendir($dir);
        if (!$dh) {
            $this->logger->info("Cannot open $dir for commiting changes");
            return false;
        }

        while (false !== ($rel_path = readdir($dh))) {
            if (isset($this->exclude[$rel_path])) continue;
            $file = "$dir/$rel_path";
            $rfile = self::REPO_FILES . "/$file";

            $stat = $this->_stat($file);
            $rstat = $this->_rstat($file);
            if ($stat === $rstat) {
                if ($stat === "dir" && $recursive) $this->_commitDir($file);
                continue;
            }

            if ($rstat && $stat === "dir") $this->_removeRecursive($rfile);
            $this->_commit($file, $stat);
            if ($stat === "dir") $this->_commitDir($file);
        }

        closedir($dh);

        /* looking for deleted entities */
        $dh = opendir($repo_dir = self::REPO_FILES . "/$dir");
        if (!$dh) {
            $this->logger->info('Cannot open ' . $repo_dir . ' for commiting changes');
            return false;
        }

        while (false !== ($rel_path = readdir($dh))) {
            if (isset($this->exclude[$rel_path])) continue;
            $file = "$dir/$rel_path";
            $rfile = self::REPO_FILES . "/$file";

            $stat = $this->_stat($file);
            $rstat = $this->_rstat($file);

            if ($rstat && !$stat) $this->_removeRecursive($rfile);
        }
        closedir($dh);

        return true;
    }

    /* Commit changes that were sent in $diff */
    private function _commitDiff()
    {
        $offset = 0;

        while (true) {
            if (($end_pos = mb_orig_strpos($this->diff, self::SEPARATOR, $offset)) === false) break;
            $chunk = mb_orig_substr($this->diff, $offset, $end_pos - $offset);
            $offset = $end_pos + mb_orig_strlen(self::SEPARATOR);
            $op = $chunk[0];
            $first_line_pos = mb_orig_strpos($chunk, "\n");
            if ($first_line_pos === false) throw new UnrealsyncException("No new line in diff chunk: $chunk");
            $first_line = mb_orig_substr($chunk, 0, $first_line_pos);
            $file = mb_orig_substr($first_line, 2);
            if (!$file) throw new UnrealsyncException("No filename in diff chunk: $chunk");
            $rfile = self::REPO_FILES . "/$file";
            $chunk = mb_orig_substr($chunk, $first_line_pos + 1);

            if ($op === 'A' || $op === 'M') {
                if ($op === 'A') $diffstat = $chunk;
                else list ($oldstat, $diffstat) = explode("\n\n", $chunk);

                if ($diffstat !== "dir" && strpos($diffstat, "symlink=") === false) {
                    $length = intval(mb_orig_substr($this->diff, $offset, self::CONTENT_HEADER_LENGTH));
                    $offset += self::CONTENT_HEADER_LENGTH + $length;
                }

                $this->_commit($file, $diffstat);
            } else if ($op === 'D') {
                $this->_removeRecursive($rfile);
            }
        }
    }

    private function _removeRecursive($path)
    {
        $stat = $this->_stat($path);
        if (!$stat) return true;
        if ($stat != "dir") return unlink($path);

        $dh = opendir($path);
        if (!$dh) return false;

        while (false !== ($rel_path = readdir($dh))) {
            if ($rel_path === "." || $rel_path === "..") continue;
            $this->_removeRecursive("$path/$rel_path");
        }

        closedir($dh);

        return rmdir($path);
    }

    private function _sendAndCommitDiff()
    {
        if ($this->is_server) throw new UnrealsyncException("Send and commit diff is not implemented on server");
        if (!$len = mb_orig_strlen($this->diff)) return;
        $this->had_changes = true;
        $this->logger->info('diff size ' . ($len > 1024 ? round($len / 1024) . ' KiB' : $len . ' bytes'));

        $this->_remoteExecuteAll(self::CMD_APPLY_DIFF, $this->diff);
        $this->_commitDiff();
        $this->diff = "";
    }

    private function _sendDirsDiff($dirs)
    {
        $this->had_changes = false;
        $this->logger->info('Changed dirs: ' . implode(" ", $dirs));
        $time = microtime(true);
        foreach ($dirs as $dir) $this->_appendDiff($dir, false);

        if (mb_orig_strlen($this->diff) > 0) $this->_sendAndCommitDiff();
        $this->logger->info('Synchronized in %.2f sec', microtime(true) - $time);
    }

    private function _cmdApplyDiff($diff)
    {
        $this->logger->info('Applying remote diff: ');
        $this->logger->_timerStart();
        $offset = 0;
        $stats = array('A' => 0, 'D' => 0, 'M' => 0);
        // We do not use explode() in order to save memory, because we need about 3 times more memory for our case
        // Diff can be large (e.g. 10 Mb) so it is totally worth it

        $recv_list = $conf_list = "";

        while (true) {
            if (($end_pos = mb_orig_strpos($diff, self::SEPARATOR, $offset)) === false) break;
            $chunk = mb_orig_substr($diff, $offset, $end_pos - $offset);
            $offset = $end_pos + mb_orig_strlen(self::SEPARATOR);
            $op = $chunk[0];
            $stats[$op]++;
            $first_line_pos = mb_orig_strpos($chunk, "\n");
            if ($first_line_pos === false) throw new UnrealsyncException("No new line in diff chunk: $chunk");
            $first_line = mb_orig_substr($chunk, 0, $first_line_pos);
            $file = mb_orig_substr($first_line, 2);
            if (!$file) throw new UnrealsyncException("No filename in diff chunk: $chunk");
            $rfile = self::REPO_FILES . "/$file";
            $chunk = mb_orig_substr($chunk, $first_line_pos + 1);
            $stat = $this->_stat($file);
            $rstat = $this->_rstat($file);
            $contents = false;
            if ($op === 'A' || $op === 'M') {
                if ($op === 'A') $diffstat = $chunk;
                else list ($oldstat, $diffstat) = explode("\n\n", $chunk);

                if ($diffstat !== "dir" && strpos($diffstat, "symlink=") === false) {
                    $length = intval(mb_orig_substr($diff, $offset, self::CONTENT_HEADER_LENGTH));
                    if ($length > self::MAX_MEMORY) throw new UnrealsyncException("Too big file, probably commucation error");
                    $offset += self::CONTENT_HEADER_LENGTH;
                    $contents = mb_orig_substr($diff, $offset, $length);
                    $offset += $length;
                }
            }

            /* TODO: write all possible cases, not just simple ones */
            if ($op === 'A') {
                $diffstat = $chunk;
                if ($stat === $diffstat) continue; // the same file was added
                $this->_writeFile($file, $diffstat, $contents);
            } else if ($op === 'D') {
                if ($stat) $this->_removeRecursive($file);
                if ($rstat) $this->_removeRecursive($rfile);
            } else if ($op === 'M') {
                list ($oldstat, $diffstat) = explode("\n\n", $chunk);
                if ($stat === $diffstat) continue; // identical changes
                $this->_writeFile($file, $diffstat, $contents);
            } else {
                throw new UnrealsyncException("Unexpected diff chunk: $chunk");
            }
        }

        $strStats = trim(($stats['A'] ? ' ' . $stats['A'] . ' files added' : '')
        . ($stats['D'] ? ' ' . $stats['D'] . ' files deleted' : '')
        . ($stats['M'] ? ' ' . $stats['M'] . ' files changed' : ''));
        if ($strStats) $this->logger->info($strStats);
        $this->logger->_timerStop("Apply remote diff done");

        $this->_commitDiff($diff);
        $this->logger->debug("Peak memory: " . memory_get_peak_usage(true));
        return null;
    }

    /*
     * Filter dirs using exclude and transform absolute paths to relative
     */
    private function _getFilteredDirs($dirs)
    {
        $curdir = getcwd();

        foreach ($dirs as $idx => $dir) {
            if ($dir === $curdir) $dir = ".";
            if (mb_orig_strpos($dir, "$curdir/") === 0) $dir = mb_orig_substr($dir, mb_orig_strlen($curdir) + 1);

            $parts = explode("/", $dir);
            foreach ($parts as $p) {
                if ($p === ".") continue;
                if (isset($this->exclude[$p])) {
                    unset($dirs[$idx]);
                    continue(2);
                }
            }

            /* check if dir is still present, because event could be delivered when dir does not exist anymore */
            $stat = $this->_stat($dir);
            if ($stat !== 'dir') {
                unset($dirs[$idx]);
                continue;
            }
            $dirs[$idx] = $dir;
        }

        return $dirs;
    }

    public function runServer()
    {
        while (true) {
            $cmd = trim($this->_fullRead(STDIN, self::CONTENT_HEADER_LENGTH));
            $len = intval($this->_fullRead(STDIN, self::CONTENT_HEADER_LENGTH));
            $data = $this->_fullRead(STDIN, $len);

            switch ($cmd) {
                case self::CMD_SHUTDOWN: $result = ''; break;
                case self::CMD_PING: $result = $this->_cmdPing(); break;
                case self::CMD_APPLY_DIFF: $result = $this->_cmdApplyDiff($data); break;
                case self::CMD_BIG_INIT: $result = $this->_cmdBigInit($data); break;
                case self::CMD_CHUNK_RCV: $result = $this->_cmdChunkRcv($data); break;
                case self::CMD_BIG_COMMIT: $result = $this->_cmdBigCommit($data); break;
                case self::CMD_BIG_ABORT: $result = $this->_cmdBigAbort(); break;
                default: throw new UnrealsyncException("Unknown cmd $cmd");
            }

            $this->_fullWrite(STDOUT, sprintf("%10u", mb_orig_strlen($result)) . $result);
            if ($cmd === self::CMD_SHUTDOWN) exit(0);
        }

        return false;
    }

    public function run()
    {
        $this->_lock();

        if ($this->is_server) {
            return $this->runServer();
        }
        file_put_contents(self::REPO_PID, getmypid());

        $threads = array();
        foreach ($this->servers as $srv => $srv_data) {
            $this->logger->info("Bootstrapping $srv");
            $threads[] = $this->_directSystem(__FILE__ . ($this->is_debug ? ' --debug' : '') . ' --bootstrap=' . escapeshellarg($srv), true);
        }
        $wait = 100;
        while (count($threads) && $wait-- > 0) {
            foreach ($threads as $idx => $thread) {
                $status = proc_get_status($thread);
                if (!$status || !$status['running']) {
                    if (isset($status['exitcode']) && $status['exitcode'] == 0) unset($threads[$idx]);
                    else throw new UnrealsyncException(var_export($status, true));
                }
            }
            usleep(100000);
        }
        if (count($threads)) throw new UnrealsyncException("Could not wait for " . var_export($threads, true) . " to finish");

        foreach ($this->servers as $srv => $srv_data) $this->startServer($srv);

        foreach ($this->servers as $srv => $srv_data) {
            $this->logger->info('Propagating merged changes to ' . $srv);
            $threads[] = $this->_directSystem(__FILE__ . ($this->is_debug ? ' --debug' : '') . ' --sync=' . escapeshellarg($srv), true);
        }
        $wait = 10000;
        while (count($threads) && $wait-- > 0) {
            foreach ($threads as $idx => $thread) {
                $status = proc_get_status($thread);
                if (!$status || !$status['running']) unset($threads[$idx]);
            }
            usleep(100000);
        }
        if (count($threads)) throw new UnrealsyncException("Could not wait for " . var_export($threads, true) . " to finish");

        $this->logger->info('Commiting local changes');
        if (!$this->_commitDir()) throw new UnrealsyncException("Cannot commit changes locally");

        $this->logger->info('Starting local watcher');
        $this->_startLocalWatcher();
        $dir_hashes = array();

        $this->logger->info('Entering event loop');
        $write = $except = array();
        while (false !== ($ln = fgets($this->watcher['pipe']))) {
            $ln = rtrim($ln);
            if ($this->os == self::OS_WIN) {
                $ln = str_replace('\\', '/', $ln);
            }
            if ($ln === "-") {
                $read = array($this->watcher['pipe']);
                if (stream_select($read, $write, $except, 0)) continue; // there is more in pipe, send later
                while (true) {
                    $this->diff = "";
                    $have_errors = false;
                    $dirs = $this->_getFilteredDirs(array_keys($dir_hashes));
                    if (!$dirs) break;
                    try {
                        $this->_sendDirsDiff($dirs);
                    } catch (UnrealsyncFileException $e) {
                        $have_errors = true;
                        $this->logger->info('Got an error during diff computation: ' . $e->getMessage());
                    }

                    if (!$have_errors) break;

                    $this->logger->info('Got errors during diff computation. Waiting 1s to try again');
                    sleep(1);
                }

                if ($this->had_changes && $this->onsync) $this->_directSystem("$this->onsync &");
                $this->had_changes = false;
                $dir_hashes = array();

                continue;
            }
            /* turn changes in separate files into changes in directories for Mac OS X watcher compatibility */
            list(, $file) = explode(" ", $ln, 2);
            if (basename($file) == '.unrealsync' && file_exists(self::REPO_KILL_FILE)) {
                break;
            }
            $dir_hashes[rtrim($file, "/")] = true;
        }
        $this->logger->info('Leaving event loop');

        return true;
    }
}

class UnrealsyncSsh {
    /** @var UnrealsyncLogger */
    private $logger;

    public function __construct(UnrealsyncLogger $logger) {
        $this->logger = $logger;
    }

    private function _getSshOptions($options)
    {
        $cmd = " -C -o BatchMode=yes -o ControlMaster=no -o ControlPath=/nonexistent ";
        if (!empty($options['username'])) $cmd .= " -o User=" . escapeshellarg($options['username']);
        if (!empty($options['port']))     $cmd .= " -o Port=" . intval($options['port']);
        return $cmd;
    }

    public function ssh($hostname, $remote_cmd, $options = array())
    {
        $cmd = "ssh " . $this->_getSshOptions($options) . " " . escapeshellarg($hostname) . " " . escapeshellarg($remote_cmd);
        $this->logger->debug($cmd);
        if (empty($options['proc_open'])) {
            exec($cmd, $out, $retval);
            if ($retval) return false;
            return implode("\n", $out);
        }

        $result = array();
        $result['pp'] = proc_open($cmd, array(array('pipe', 'r'), array('pipe', 'w'), STDERR), $pipes);
        if (!$result['pp']) return false;

        $result['write_pipe'] = $pipes[0];
        $result['read_pipe'] = $pipes[1];

        return $result;
    }

    public function scp($hostname, $local_file, $remote_file, $options = array())
    {
        $file_args = array();
        if (is_array($local_file)) {
            foreach ($local_file as $file) $file_args[] = escapeshellarg($file);
        } else {
            $file_args[] = escapeshellarg($local_file);
        }
        $cmd = "scp " . $this->_getSshOptions($options) . " " . implode(" ", $file_args) . " " . escapeshellarg("$hostname:$remote_file");
        $this->logger->debug($cmd);
        exec($cmd, $out, $retval);
        return $retval ? false : true;
    }
}

class UnrealsyncLogger {
    const LOG_DEBUG = 9;
    const LOG_INFO = 8;

    private $isatty = false;
    private $timers = array();
    private $level = null;
    private $hostname = 'localhost';
    private static $instance = null;

    public function __construct($level) {
        $this->level = $level;
        if (!function_exists('posix_isatty') && is_callable('dl')) @dl('posix.' . PHP_SHLIB_SUFFIX);
        if (is_callable('posix_isatty')) $this->isatty = posix_isatty(0) && posix_isatty(1);
        $this->hostname = trim(`hostname -f`);
        self::$instance = $this;
    }

    public function _timerStart($msg = null)
    {
        if ($msg) $this->debug($msg);
        $this->timers[] = microtime(true);
    }

    public function _timerStop($msg)
    {
        $time = round((microtime(true) - array_pop($this->timers)) * 1000);
        $this->debug(sprintf("\33[32m%4s ms\33[0m %s", $time, $msg));
        return $time;
    }

    public function debug($msg)
    {
        if ($this->level >= self::LOG_DEBUG) $this->info($msg);
    }

    public function info($msg) {
        $host = $this->hostname ? (($this->isatty ? "\33[35m" : '') . $this->hostname . '$ ' . ($this->isatty ? "\33[0m" : '')) : '';
        if (func_num_args() > 1) {
            $msg = call_user_func_array('sprintf', func_get_args());
        }
        $msg = (!$this->isatty ? date('Y-m-d H:i:s ') : '') . $host . $msg . "\n";
        return fwrite(STDERR, $msg);
    }

    public function error($msg) {
        $this->info("\33[31m$msg\33[0m");
    }

    public static function exception(Exception $e) {
        if (!self::$instance instanceof self) return;
        self::$instance->error(get_class($e) . $e->getMessage() . "\n" . $e->getTraceAsString());
    }
}

class UnrealsyncWizard {
    /** @var UnrealsyncSsh */
    private $ssh;
    private $tmp;

    /**
     * @param $question
     * @param string $default
     * @param mixed $validation Either array of valid answers or function to check the result
     * @throws UnrealsyncException
     * @return string
     */
    public function ask($question, $default = '', $validation = null)
    {
        if ($default) $question .= " \33[36m[$default]\33[0m";

        while (true) {
            echo $question . ': ';
            $answer = fgets(STDIN);
            if ($answer === false || strpos($answer, "\n") === false) {
                throw new UnrealsyncException("Could not read line from STDIN");
            }
            $answer = rtrim($answer);
            if (!strlen($answer)) $answer = $default;
            if (!$validation) return $answer;

            if (is_string($validation) && method_exists($this, $validation)) {
                switch ($validation) {
                    case '_checkYN': $result = $this->_checkYN($answer); break;
                    case '_checkSSHBinary': $result = $this->_checkSSHBinary($answer); break;
                    case '_configWizardAskRemoteAddress': $result = $this->_configWizardAskRemoteAddress($answer); break;
                    case '_verifyRemoteDir': $result = $this->_verifyRemoteDir($answer); break;
                    default: throw new UnrealsyncException("Should never happen: $validation");
                }
                if (!$result) continue;
                return $answer;
            } else if (is_array($validation)) {
                if (!in_array($answer, $validation)) {
                    echo 'Valid options are: ' . implode(', ', $validation);
                    continue;
                }
                return $answer;
            } else {
                throw new UnrealsyncException("Internal error: Incorrect validation argument");
            }
        }
    }

    private function _checkYN($answer)
    {
        if (in_array(strtolower($answer), array('yes', 'no', 'y', 'n'))) return true;
        echo "\33[31mPlease write either yes or no\33[0m\n";
        return false;
    }

    public function askYN($question, $default = 'Y')
    {
        $answer = $this->ask($question, $default, '_checkYN');
        return in_array(strtolower($answer), array('yes', 'y'));
    }

    private function _checkSSHBinary($path)
    {
        $host = $this->tmp['host'];
        $ssh_options = $this->tmp['ssh_options'];
        $result = Unrealsync::ssh($host, escapeshellarg($path) . " --run 'echo PHP_SAPI;'", $ssh_options);
        if ($result === false) return false;

        if (trim($result) != "cli") {
            echo "It is not PHP CLI binary ;)\n";
            return false;
        }

        return true;
    }

    private function _configWizardAskRemoteAddress($str)
    {
        $os = $php_location = $username = $host = $port = '';
        $this->tmp = array(
            'os' => &$os, 'php_location' => &$php_location, 'username' => &$username, 'host' => &$host, 'port' => &$port
        );

        if (strpos($str, ":") !== false) {
            list($str, $port) = explode(":", $str, 2);
            if ($port === (string)(int)$port) {
                echo "Port must be numeric\n";
                return false;
            }
        }

        if (strpos($str, "@") !== false) {
            list($username, $host) = explode("@", $str, 2);
        } else {
            $host = $str;
        }

        $this->tmp['ssh_options'] = $ssh_options = array('username' => $username, 'port' => $port);

        echo "Checking connection\n";
        $result = $this->ssh->ssh($host, 'echo uname=`uname`; echo php=`which php`; echo pwd=`pwd`', $ssh_options);
        if ($result === false) {
            echo "Cannot connect\n";
            return false;
        }

        echo "Connection is OK\n";

        $variables = array('uname' => '', 'php' => '', 'pwd' => '');
        foreach (explode("\n", $result) as $ln) {
            list($k, $v) = explode("=", $ln, 2);
            $variables[$k] = $v;
        }
        if (!empty($variables['pwd'])) {
            $this->tmp['dir'] = $variables['pwd'];
        }

        if (!in_array($os = $variables['uname'], array('Linux', 'Darwin', 'FreeBSD'))) {
            echo "Remote OS $os is not supported, sorry\n";
            return false;
        }

        if (!$variables['php']) {
            $this->tmp['php'] = $this->ask(
                'Where is PHP? Provide path to "php" binary',
                '/usr/local/bin/php',
                '_checkSSHBinary'
            );
        }

        return true;
    }

    private function _configWizardSSH()
    {
        $this->ask('Remote SSH server address', '', '_configWizardAskRemoteAddress');
        return $this->tmp;
    }

    private function _verifyRemoteDir($dir)
    {
        echo "Checking remote directory\n";
        $dir = escapeshellarg($dir);
        $cmd = "if [ -d $dir ]; then echo Exists; else exit 1; fi; if [ -w $dir ]; then echo Writable; fi";
        $result = $this->ssh->ssh($this->tmp['host'], $cmd, $this->tmp['ssh_options']);
        if (strpos($result, "Exists") === false) {
            echo "Remote path $dir is not a directory\n";
            return false;
        }
        if (strpos($result, "Writable") === false) {
            echo "Remote directory $dir exists but it is not writable for you\n";
            return false;
        }
        echo "Remote directory is OK\n";
        return true;
    }

    private function _configWizardRemoteDir($ssh_options)
    {
        $this->tmp['ssh_options'] = $ssh_options;
        return $this->ask(
            "Remote directory to be synced",
            $this->tmp['dir'] ? $this->tmp['dir'] . DIRECTORY_SEPARATOR . basename(getcwd()) : getcwd(),
            '_verifyRemoteDir'
        );
    }

    private function _askSyncDirection()
    {
        $sync_direction = false;

        echo "Only one-way offline synchronization is supported\n";
        echo "You can choose either local or remote copies to be propagated.\n";
        echo "If you choose \33[33m" . Unrealsync::SYNC_FROM_LOCAL . "\33[0m, all changes on \33[33m" . $this->tmp['host'] . "\33[0m will be LOST and vice versa\n";
        $is_ok = false;
        while (!$is_ok) {
            $sync_direction = $this->ask(
                "Please choose primary repository (\33[33m" . Unrealsync::SYNC_FROM_LOCAL . "\33[0m or \33[33m" . Unrealsync::SYNC_FROM_REMOTE . "\33[0m)",
                Unrealsync::SYNC_FROM_LOCAL,
                array(Unrealsync::SYNC_FROM_LOCAL, Unrealsync::SYNC_FROM_REMOTE)
            );

            if ($sync_direction === Unrealsync::SYNC_FROM_LOCAL) $q = "All changes (if any) at " . $this->tmp['host'] . " will be lost. Continue?";
            else $q = "All local changes will be lost. Continue? ";

            if ($this->askYN($q)) $is_ok = true;
        }

        return $sync_direction;
    }

    private function _saveIni($config) {
        $ini = '';
        foreach ($config as $sect => $settings) {
            $ini .= "[$sect]\n";
            foreach ($settings as $name => $value) {
                if (is_array($value)) {
                    foreach ($value as $item) {
                        $ini .= "${name}[] = $item\n";
                    }
                } else {
                    $ini .= "$name = $value\n";
                }
            }
            $ini .= "\n";
        }
        if (file_put_contents(Unrealsync::REPO_CLIENT_CONFIG, $ini) !== mb_orig_strlen($ini)) {
            return false;
        }
        return true;
    }

    public function configWizard()
    {
        $isatty = false;
        if (!function_exists('posix_isatty') && is_callable('dl')) @dl('posix.' . PHP_SHLIB_SUFFIX);
        if (is_callable('posix_isatty')) $isatty = posix_isatty(0) && posix_isatty(1);
        if (!$isatty) return false;

        $logger = new UnrealsyncLogger(UnrealsyncLogger::LOG_INFO);
        $this->ssh = new UnrealsyncSsh($logger);

        echo "Welcome to unrealsync setup wizard\n";
        echo "Unrealsync is utility to do bidirectional sync between several computers\n\n";
        echo "It is highly recommended to have SSH keys set up for passwordless authentication\n";
        echo "Read more about it at http://mah.everybody.org/docs/ssh\n\n";

        $config = array('general_settings' =>
            array('exclude[]' => '.unrealsync')
        );
        do {
            $ssh_opts = $this->_configWizardSSH();
            $remote_dir = $this->_configWizardRemoteDir($ssh_opts);
            $sync_direction = $this->_askSyncDirection();

            $host = $ssh_opts['host'];
            $config[$host] = array(
                'host' => $host,
                'dir' => $remote_dir,
                'os' => $ssh_opts['os'],
                'sync_direction' => $sync_direction,
            );
            if (!empty($ssh_opts['port'])) $config[$host]['port'] = $ssh_opts['port'];
            if (!empty($ssh_opts['username'])) $config[$host]['username'] = $ssh_opts['username'];
            if (!empty($ssh_opts['php'])) $config[$host]['php'] = $ssh_opts['php'];
        } while ($this->askYN('Do you want to configure additional settings?', 'N'));

        if (!mkdir(Unrealsync::REPO)) {
            throw new UnrealsyncException("Cannot create directory " . Unrealsync::REPO);
        }
        if (!$this->_saveIni($config)) {
            throw new UnrealsyncException("Cannot write to " . Unrealsync::REPO_CLIENT_CONFIG);
        }

        if (!$this->askYN("Going to begin sync now. Continue?")) exit(0);
        return true;
    }

    public function configCommand($args) {
        if (!file_exists(Unrealsync::REPO_CLIENT_CONFIG)) {
            $this->configWizard();
            return;
        }
        $ini = parse_ini_file(Unrealsync::REPO_CLIENT_CONFIG, true);
        foreach ($ini as $section => $settings) {
            if ($section == 'general_settings') continue;
            printf("%-20s %s\n", $section, isset($settings['disable']) ? "OFF" : "ON");;
        }
        if (!isset($args[2]) || !isset($args[3])) {
            return;
        }
        $host = $args[2];
        $name = $args[3];
        $value = isset($args[4]) ? $args[4] : 'true';
        if ($name == 'enable') unset($ini[$host]['disable']);
        else $ini[$host][$name] = $value;
        $this->_saveIni($ini);
    }
}
