<?php
include_once "./vendor/autoload.php";

use phpseclib3\Crypt\RSA;

class Crypt{

    /**
     * @var RSA $rsa
     */
    public $rsa = null;

    protected $private_file = "private.pem";

    protected $passwd_file = "passwd";

    protected $encode_file = "encode";

    protected $decode_file = "decode";

    public function __construct()
    {
        $this->load_private();  
    }

    public function load_private(){
        if(file_exists($this->private_file)){
            $private_key = file_get_contents($this->private_file);
            $private = RSA::load($private_key);
        }else{
            $private = RSA::createKey(2048);
            file_put_contents($this->private_file,$private);
        }
        $this->rsa = $private;
    }

    public function encode(){
        $plaintext = file_get_contents($this->passwd_file);
        $encode = $this->rsa->getPublicKey()->encrypt($plaintext);
        file_put_contents($this->encode_file,base64_encode($encode));
    }


    public function decode(){
        $plaintext = file_get_contents($this->encode_file);
        $decode = $this->rsa->decrypt(base64_decode($plaintext));
        file_put_contents($this->decode_file,$decode);
    }


    public static function __callStatic($name, $arguments)
    {
        $opt = getopt("m:");
        if(!isset($opt['m'])){
            throw new \Exception("缺少method参数 -m!");
        }

        $method = $opt['m'];
        $crypt = new Crypt();
        if(!method_exists($crypt,$method)){
            throw new \Exception("不存在方法!");
        }
        $crypt->$method();
    }
}

Crypt::start();