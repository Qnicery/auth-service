package org.example.auth.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

@Component
class JwtTokenProvider {
    private val secret = "802734bb4a9971f73d244f9af249971f4e48318d7ce2735a2f71ff1dbbaa2e98"
    private val secretKey: SecretKey = Keys.hmacShaKeyFor(secret.toByteArray())
    private val validityInMs = 1000 * 60 * 60 * 24 * 7

    fun createToken(username: String): String {
        val claims = Jwts.claims().setSubject(username)
        val now = Date()
        val validity = Date(now.time + validityInMs)

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(secretKey)
            .compact()
    }

    fun getUsername(token: String): String =
        Jwts.parserBuilder().setSigningKey(secretKey).build()
            .parseClaimsJws(token).body.subject

    fun validateToken(token: String): Boolean {
        return try {
            Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
            true
        } catch (e: Exception) {
            false
        }
    }

    fun getUsernameFromToken(token: String): String {
        val cleanToken = if (token.startsWith("Bearer ")) {
            token.substring(7)
        } else {
            token
        }.trim()

        println("TOKEN: $cleanToken")
        println("TOKEN: $token")

        val claims = Jwts.parserBuilder()
            .setSigningKey(secret.toByteArray())
            .build()
            .parseClaimsJws(cleanToken)
            .body

        return claims.subject
    }
}
