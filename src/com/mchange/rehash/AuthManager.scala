package com.mchange.rehash

import java.security.SecureRandom
import scala.collection.{immutable,mutable}

object AuthManager:

  def costFactor( bch : BCryptHash ) : Int =
    val hashArr = bch.unsafeInternalArray
    val intChars = Array( hashArr(4), hashArr(5) ) // two character human-readable cost factor in bcrypt hashes
    new String( intChars ).toInt

  def version( bch : BCryptHash ) : Authenticator.BCryptVersion =
    val hashArr = bch.unsafeInternalArray
    val tagChars = Array( hashArr(1), hashArr(2) ) // two character human-readable cost factor in bcrypt hashes
    val tag = new String( tagChars )
    Authenticator.BCryptVersion.forTag( tag ).getOrElse( throw new UnknownBCryptVersion("Unknown BCrypt version: " + tag) )

  object Spec:
    def apply( bch : BCryptHash ) : Spec = Spec( version( bch ), costFactor( bch ) )
  case class Spec( version : Authenticator.BCryptVersion, costFactor : Int )

class AuthManager[UID](
  currentSpec : AuthManager.Spec,
  longPasswordStrategyForCurrentOrHistoricalSpec : Map[AuthManager.Spec, Authenticator.LongPasswordStrategy],
  entropy : java.security.SecureRandom
):

  val currentAuthenticator =
    val AuthenticatorWithStatus( am, isCurrent ) = AuthenticatorWithStatus.forSpec( currentSpec )
    assert( isCurrent )
    am

  object AuthenticatorWithStatus:
    // MT: synchronized on this' lock
    private val memoized : mutable.HashMap[AuthManager.Spec,AuthenticatorWithStatus] = new mutable.HashMap()

    def forSpec( spec : AuthManager.Spec ) : AuthenticatorWithStatus =
      val lps = longPasswordStrategyForCurrentOrHistoricalSpec.getOrElse( spec, throw new UnexpectedBCryptHashSpec("This application has never supported bcrypt hashes of type " + spec) )
      this.synchronized:
        memoized.getOrElseUpdate( spec, new AuthenticatorWithStatus( new Authenticator( spec.costFactor, spec.version, lps, entropy ), spec == currentSpec ) )

    def forHash( hash : BCryptHash ) : AuthenticatorWithStatus =
      forSpec( AuthManager.Spec(hash) )
  case class AuthenticatorWithStatus( authManager : Authenticator, isCurrent : Boolean )

  def initialPasswordHash( uid : UID, password : Password ) : BCryptHash =
    currentAuthenticator.hashForPassword(password)

  def overwriteNewPassword( uid : UID, password : Password, storeHash : (UID, BCryptHash) => Unit ) : Unit =
    val bchash = currentAuthenticator.hashForPassword(password)
    storeHash( uid, bchash )

  def verifyRehash( uid : UID, password : Password, fetchHash : UID => Option[BCryptHash], storeHash : (UID, BCryptHash) => Unit ) : VerificationResult =
    import VerificationResult.*
    fetchHash( uid ) match
      case Some( hash ) =>
        val amws = AuthenticatorWithStatus.forHash(hash)
        val out = amws.authManager.verifyPassword( password, hash )
        if !amws.isCurrent then storeHash( uid, currentAuthenticator.hashForPassword( password ) )
        if out then OK else WrongPassword
      case None =>
        UserNotFound
