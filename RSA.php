<?php
namespace phprsa;

/**
 * RSA şifreleme için kullanılacak sınıftır. Orjinaline aşağıdaki linkten ulaşabilirsiniz, ben biraz daha kolaylaştırıyorum.
 * Yorumları da anladığım kadarıyla yazmaya çalıştım. 
 * 
 * @link https://github.com/ideasoft/RSA buraya da repo açtım. geliştirmeleri bu repoya yaparız. 
 * 
 * @author Emre Macit
 * 
 * @link http://www.phpkode.com/source/s/rsa/rsa/rsa.class.php
 *  
 * Prime-Numbers.org provide small prime numbers list. 
 * You can browse all small prime numbers(small than 10,000,000,000) there. 
 * There's totally 455042511 prime numbers.
 * http://www.prime-numbers.org/
 */
class RSA {

	/**
	 * Generate edilen key'leri tutmaya yarayan array
	 * @var array (0,1,2) elemanlarından oluşur.
	 */
	private $_keys = array ();

	/**
     * Function for generating keys. Return array where
     * $array[0] -> modulo N
     * $array[1] -> public key E
     * $array[2] -> private key D
     * Public key pair is N and E
     * Private key pair is N and D
     * 
     * @link http://prime-numbers.org/prime-number-184950000-184955000.htm buradan birbirine çok yakın 2 tane asal sayı seçin.
     * 
     * @param int $p | asal sayı.
     * @param int $q | asal sayı.
     * 
     * @return array
     */
	public function generateKeys($p, $q){
		$n = bcmul( $p, $q );
		
		//m (we need it to calculate D and E) 
		$m = bcmul( bcsub( $p, 1 ), bcsub( $q, 1 ) );
		
		// Public key  E 
		$e = $this->_findE( $m );
		
		// Private key D
		$d = $this->_extend( $e, $m );
		
		$this->_keys = array ( $n, $e, $d );
		
		return $this->_keys;
	}

	/**
     * Standard method of calculating D
     * D = E-1 (mod N)
     * It's presumed D will be found in less then 16 iterations 
     * 
     * @return number
     */
	private function _extend($Ee, $Em){
		$u1 = '1';
		$u2 = '0';
		$u3 = $Em;
		$v1 = '0';
		$v2 = '1';
		$v3 = $Ee;
		
		while ( bccomp( $v3, 0 ) != 0 ) {
			$qq = bcdiv( $u3, $v3, 0 );
			$t1 = bcsub( $u1, bcmul( $qq, $v1 ) );
			$t2 = bcsub( $u2, bcmul( $qq, $v2 ) );
			$t3 = bcsub( $u3, bcmul( $qq, $v3 ) );
			$u1 = $v1;
			$u2 = $v2;
			$u3 = $v3;
			$v1 = $t1;
			$v2 = $t2;
			$v3 = $t3;
			$z = '1';
		}
		
		$uu = $u1;
		$vv = $u2;
		
		if (bccomp( $vv, 0 ) == - 1) {
			$inverse = bcadd( $vv, $Em );
		} else {
			$inverse = $vv;
		}
		
		return $inverse;
	}

	/**
     * This function return Greatest Common Divisor for $e and $m numbers 
     * @return number
     */
	private function _greatestCommonDivisor($e, $m){
		$y = $e;
		$x = $m;
		
		while ( bccomp( $y, 0 ) != 0 ) {
			// modulus function
			$w = bcsub( $x, bcmul( $y, bcdiv( $x, $y, 0 ) ) );
			;
			$x = $y;
			$y = $w;
		}
		
		return $x;
	}

	/**
     * Calculating E under conditions:
     * _greatestCommonDivisor(N,E) = 1 and 1<E<N
     * 
     * @return number
     */
	private function _findE($m){
		$e = '3';
		if (bccomp( $this->_greatestCommonDivisor( $e, $m ), '1' ) != 0) {
			$e = '5';
			$step = '2';
			
			while ( bccomp( $this->_greatestCommonDivisor( $e, $m ), '1' ) != 0 ) {
				$e = bcadd( $e, $step );
				
				if ($step == '2') {
					$step = '4';
				} else {
					$step = '2';
				}
			}
		}
		
		return $e;
	}

	/**
	 * Şifreleme metodudur.
     * ENCRYPT function returns
     * X = M^E (mod N)
     * @param string $m | encode edeceğiniz string
     * @param int $s | paket sayısını belirleyen çarpan. bilmiyorsanız, 3,4,5 bişey gönderin. 1,2 veya 7 den büyük değerler için doğru çalışmaz.
     * @return string
     */
	public function encrypt($m, $s = 3){
		if (empty( $this->_keys )) {
			throw new \Exception( 'You have to generate keys first' );
		}
		$e = $this->_keys [1];
		$n = $this->_keys [0];
		$coded = '';
		$max = strlen( $m );
		$packets = ceil( $max / $s );
		
		for($i = 0; $i < $packets; $i ++) {
			$packet = substr( $m, $i * $s, $s );
			$code = '0';
			
			for($j = 0; $j < $s; $j ++) {
				if (isset( $packet [$j] )) {
					$left_operand = ord( $packet [$j] );
				} else {
					$left_operand = 0;
				}
				$code = bcadd( $code, bcmul( $left_operand, bcpow( '256', $j ) ) );
			}
			
			$code = bcpowmod( $code, $e, $n, 0 );
			$coded .= $code . ' ';
		}
		
		return trim( $coded );
	}

	/**
	 * Şifreyi çözüp döndürür.
     * DECRYPT function returns
     * M = X^D (mod N)
     * 
     * @return string
     */
	public function decrypt($c){
		if (empty( $this->_keys )) {
			throw new \Exception( 'You have to generate keys first' );
		}
		$d = $this->_keys [2];
		$n = $this->_keys [0];
		$coded = explode( ' ', $c );
		$message = '';
		$max = count( $coded );
		
		for($i = 0; $i < $max; $i ++) {
			$code = bcpowmod( $coded [$i], $d, $n, 0 );
			
			while ( bccomp( $code, '0' ) != 0 ) {
				$ascii = bcmod( $code, '256' );
				$code = bcdiv( $code, '256', 0 );
				$message .= chr( $ascii );
			}
		}
		
		return $message;
	}

	/**
     * bir stringin imzasını oluşturup döndürür.
	 * Digital signature
     * @uses $this->encrypt
     * 
     * @param string $message
     * @return string
     */
	public function sign($message){
		$messageDigest = md5( $message );
		$signature = $this->encrypt( $messageDigest, 3 );
		return $signature;
	}

	/**
     * stringin doğru imzaya sahip olduğunu teyid eder.  (ve ya imzanın doğru stringe ait olup olmadığını)
     * @uses $this->decrypt
     * 
     * @param string $message
     * @param string $signature
     * @return boolean
     */
	public function prove($message, $signature){
		$messageDigest = $this->decrypt( $signature );
		if ($messageDigest == md5( $message )) {
			return true;
		} else {
			return false;
		}
	}

	/**
     * Bir dosya imzasını oluşturup döndürür.
     * @uses $this->encrypt
     * 
     * @param string $fileName
     * @return string
     */
	public function signFile($fileName){
		$messageDigest = md5_file( $fileName );
		$signature = $this->encrypt( $messageDigest, 3 );
		return $signature;
	}

	/**
     * Sign edilen bir dosyanın imzasının doğru imza olduğunu teyid eder.
     * @uses $this->decrypt
     *  
     * @param string $fileName
     * @param string $signature
     * @return boolean
     */
	public function proveFile($fileName, $signature){
		$messageDigest = $this->decrypt( $signature );
		if ($messageDigest == md5_file( $fileName )) {
			return true;
		} else {
			return false;
		}
	}

}
