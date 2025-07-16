package com.mchange.reauth

import scala.annotation.targetName

object BCryptHash:
  def apply( chars : Array[Char] ) : BCryptHash = // don't inline with require
    require( chars.length == 60, "A BCrypt salted hash must contain precisely 60 characters, provided hash contains " + chars.length )
    chars
opaque type BCryptHash = Array[Char]

extension( bchash : BCryptHash )
  @targetName("bcryptHashUnsafeInternalArray") private[reauth] inline def unsafeInternalArray : Array[Char] = bchash

object Password:
  inline def apply( s : String ) : Password = s
opaque type Password = String

extension( password : Password )
  @targetName("passwordToString") private[reauth] inline def str : String = password
  
