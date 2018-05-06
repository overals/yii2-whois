<?php

namespace overals\whois;

use yii\base\BaseObject;

class Whois extends BaseObject
{
    private $domain;
    private $TLDs;
    private $subDomain;
    private $servers;
    private $errors;
    private $latestResult;

    /**
     * @param string $domain full domain name (without trailing dot)
     */
    public function __construct($domain)
    {
        $this->domain = $domain;
        // check $domain syntax and split full domain name on subdomain and TLDs
        if (
            preg_match('/^([\p{L}\d\-]+)\.((?:[\p{L}\-]+\.?)+)$/ui', $this->domain, $matches)
            || preg_match('/^(xn\-\-[\p{L}\d\-]+)\.(xn\-\-(?:[a-z\d-]+\.?1?)+)$/ui', $this->domain, $matches)
        ) {
            $this->subDomain = $matches[1];
            $this->TLDs = $matches[2];
        } else
            throw new \InvalidArgumentException("Invalid $domain syntax");
        // setup whois servers array from json file
        $this->servers = json_decode(file_get_contents( __DIR__.'/whois.servers.json' ), true);
    }

    /**
     * @return string
     */
    public function info()
    {
        $this->clearErrors();
        if ($this->isValid()) {
            $whois_server = $this->servers[$this->TLDs][0];

            // If TLDs have been found
            if ($whois_server != '') {

                // if whois server serve replay over HTTP protocol instead of WHOIS protocol
                if (preg_match("/^https?:\/\//i", $whois_server)) {

                    // curl session to get whois reposnse
                    $ch = curl_init();
                    $url = $whois_server . $this->subDomain . '.' . $this->TLDs;
                    curl_setopt($ch, CURLOPT_URL, $url);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

                    $data = curl_exec($ch);

                    if (curl_error($ch)) {
                        $this->addError("Connection error!");
                        return "Connection error!";
                    } else {
                        $string = strip_tags($data);
                    }
                    curl_close($ch);

                } else {

                    // Getting whois information
                    $fp = fsockopen($whois_server, 43);
                    if (!$fp) {
                        $this->addError("Connection error!");
                        return "Connection error!";
                    }

                    $dom = $this->subDomain . '.' . $this->TLDs;
                    fputs($fp, "$dom\r\n");

                    // Getting string
                    $string = '';

                    // Checking whois server for .com and .net
                    if ($this->TLDs == 'com' || $this->TLDs == 'net') {
                        while (!feof($fp)) {
                            $line = trim(fgets($fp, 128));

                            $string .= $line;

                            $lineArr = explode (":", $line);

                            if (strtolower($lineArr[0]) == 'whois server') {
                                $whois_server = trim($lineArr[1]);
                            }
                        }
                        // Getting whois information
                        $fp = fsockopen($whois_server, 43);
                        if (!$fp) {
                            return "Connection error!";
                        }

                        $dom = $this->subDomain . '.' . $this->TLDs;
                        fputs($fp, "$dom\r\n");

                        // Getting string
                        $string = '';

                        while (!feof($fp)) {
                            $string .= fgets($fp, 128);
                        }

                        // Checking for other tld's
                    } else {
                        while (!feof($fp)) {
                            $string .= fgets($fp, 128);
                        }
                    }
                    fclose($fp);
                }

                $string_encoding = mb_detect_encoding($string, "UTF-8, ISO-8859-1, ISO-8859-15", true);
                $string_utf8 = mb_convert_encoding($string, "UTF-8", $string_encoding);

                $this->latestResult = htmlspecialchars($string_utf8, ENT_COMPAT, "UTF-8", true);

                return $this->latestResult;
            } else {
                $this->addError('No whois server for this tld in list!');
                return 'No whois server for this tld in list!';
            }
        } else {
            $this->addError("Domain name isn't valid!");
            return "Domain name isn't valid!";
        }
    }

    /**
     * @return string
     */
    public function htmlInfo()
    {
        return nl2br($this->info());
    }

    /**
     * @return string full domain name
     */
    public function getDomain()
    {
        return $this->domain;
    }

    /**
     * @return string top level domains separated by dot
     */
    public function getTLDs()
    {
        return $this->TLDs;
    }

    /**
     * @return string return subdomain (low level domain)
     */
    public function getSubDomain()
    {
        return $this->subDomain;
    }

    /**
     * @return array
     */
    public function getErrors(){
        return array('errors' => $this->errors);
    }

    /**
     * @param $msg
     */
    private function addError($msg) {
        $this->errors[] = $msg;
    }

    private function clearErrors() {
        $this->errors = array();
    }

    public function getLatestResult()
    {
        return $this->latestResult;
    }

    /**
     * @return bool
     */
    public function isAvailable()
    {
        $whois_string = $this->info();
        $not_found_string = '';
        if (isset($this->servers[$this->TLDs][1])) {
           $not_found_string = $this->servers[$this->TLDs][1];
        }

        $whois_string2 = @preg_replace('/' . $this->domain . '/', '', $whois_string);
        $whois_string = @preg_replace("/\s+/", ' ', $whois_string);

        $array = explode (":", $not_found_string);
        if ($array[0] == "MAXCHARS") {
            if (strlen($whois_string2) <= $array[1]) {
                return true;
            } else {
                return false;
            }
        } else {
            if (preg_match("/" . $not_found_string . "/i", $whois_string)) {
                return true;
            } else {
                return false;
            }
        }
    }

    /**
     * @return bool
     */
    public function isValid()
    {
        if (
            isset($this->servers[$this->TLDs][0])
            && strlen($this->servers[$this->TLDs][0]) > 6
        ) {
            $tmp_domain = strtolower($this->subDomain);
            if (
                preg_match("/^[a-z0-9\-]{3,}$/", $tmp_domain)
                && !preg_match("/^-|-$/", $tmp_domain) //&& !preg_match("/--/", $tmp_domain)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array|bool
     */
    public function checkAge(){
        $whois_string = $this->info();
        if(!$this->errors) {
            if (preg_match('/Creation Date:(.*)/i', $whois_string, $match) ||
                preg_match('/Created On:(.*)/i', $whois_string, $match) ||
                preg_match('/Domain Registration Date:(.*)/i', $whois_string, $match) ||
                preg_match('/Registered on:(.*)/i', $whois_string, $match) ||
                preg_match('/Creation date:(.*)/i', $whois_string, $match) ||
                preg_match('/registration:(.*)/i', $whois_string, $match) ||
                preg_match('/Created:(.*)/i', $whois_string, $match) ||
                preg_match('/Domain record activated:(.*)/i', $whois_string, $match) ||
                preg_match('/Create Date:(.*)/i', $whois_string, $match)
            ) {
                return array('Creation Date'=>$match[1],'Age'=>$this->getAge($match[1]));
            /*} elseif (preg_match('/Created On:(.*)/i', $whois_string, $match)) {
                return $this->getAge($match[1]);
            } elseif (preg_match('/Domain Registration Date:(.*)/i', $whois_string, $match)) {
                return $this->getAge($match[1]);
            } elseif (preg_match('/Registered on:(.*)/i', $whois_string, $match)) {
                return $this->getAge($match[1]);
            } elseif (preg_match('/Creation date:(.*)/i', $whois_string, $match)) {
                return $this->getAge($match[1]);
            } elseif (preg_match('/registration:(.*)/i', $whois_string, $match)) {
                return $this->getAge($match[1]);
            } elseif (preg_match('/Created:(.*)/i', $whois_string, $match)) {
                return $this->getAge($match[1]);
            } elseif (preg_match('/Domain record activated:(.*)/i', $whois_string, $match)) {
                return $this->getAge($match[1]);
            } elseif (preg_match('/Create Date:(.*)/i', $whois_string, $match)) {
                return $this->getAge($match[1]);*/
            } else {
                $this->addError("Domain creation date was not found!");
                return false;
            }
        }
        else{
            return false;
        }
    }

    /**
     * @param $date
     * @return string
     */
    private function getAge($date){
        $cdate = date('Y-m-d H:i:s', strtotime(trim($date)));
        $interval = date_diff(date_create(), date_create($cdate));
        return $interval->format("%Y Year, %M Months, %d Days");
    }
}
