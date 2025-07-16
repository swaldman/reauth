package com.mchange.reauth

class ReauthException( message : String, cause : Throwable = null ) extends Exception( message, cause )

final class UnknownBCryptVersion( message : String, cause : Throwable = null )     extends ReauthException( message, cause )
final class UnexpectedBCryptHashSpec( message : String, cause : Throwable = null ) extends ReauthException( message, cause )

