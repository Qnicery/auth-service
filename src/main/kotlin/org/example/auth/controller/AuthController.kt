package org.example.auth.controller

import org.example.auth.dto.request.ChangeDataRequest
import org.example.auth.dto.request.ChangePasswordRequest
import org.example.auth.dto.request.LoginRequest
import org.example.auth.dto.request.RegisterRequest
import org.example.auth.dto.response.AuthResponse
import org.example.auth.dto.response.ErrorResponse
import org.example.auth.security.JwtTokenProvider
import org.example.auth.dao.AuthDao
import org.example.auth.util.toDto
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.*
import org.springframework.web.server.ResponseStatusException


@RestController
@RequestMapping("/api/v1/auth")
class AuthController(
    private val passwordEncoder: PasswordEncoder,
    private val jwtTokenProvider: JwtTokenProvider,
    private val authDao: AuthDao
) {

    companion object {
        const val TOKEN: String = "Authorization"
    }

    @PostMapping("/register")
    fun register(@RequestBody request: RegisterRequest): ResponseEntity<*> {
        if (authDao.fetchByUsername(request.username).size != 0) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(
                    ErrorResponse(
                        status = HttpStatus.CONFLICT.value(),
                        error = "Conflict",
                        message = "Username already exists"
                    )
                )
        }

        if (authDao.fetchByEmail(request.email).size != 0) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(
                    ErrorResponse(
                        status = HttpStatus.CONFLICT.value(),
                        error = "Conflict",
                        message = "Email already exists"
                    )
                )
        }

        val encodedPassword = passwordEncoder.encode(request.password)
        val user = org.example.auth.model.User(
            username = request.username,
            password = encodedPassword,
            email = request.email
        )

        val createdUser = authDao.createUser(user)
        val token = jwtTokenProvider.createToken(createdUser.username)

        return ResponseEntity.ok(AuthResponse(token = token))
    }

    @PostMapping("/login")
    fun login(@RequestBody request: LoginRequest): ResponseEntity<*> {
        val user = authDao.fetchByUsername(request.username).firstOrNull()
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(
                    ErrorResponse(
                        status = HttpStatus.UNAUTHORIZED.value(),
                        error = "Unauthorized",
                        message = "Invalid username or password"
                    )
                )

        if (!passwordEncoder.matches(request.password, user.password)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(
                    ErrorResponse(
                        status = HttpStatus.UNAUTHORIZED.value(),
                        error = "Unauthorized",
                        message = "Invalid username or password"
                    )
                )
        }

        val token = jwtTokenProvider.createToken(user.username)
        return ResponseEntity.ok(AuthResponse(token = token))
    }

    @GetMapping("/logout")
    fun logout(): ResponseEntity<*> {
        SecurityContextHolder.clearContext()
        return ResponseEntity.ok(mapOf("message" to "Logged out successfully"))
    }

    @PutMapping("/change/password")
    fun changePassword(@RequestBody request: ChangePasswordRequest): ResponseEntity<*> {
        val authentication: Authentication? = SecurityContextHolder.getContext().authentication
        val username = authentication?.name
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(
                    ErrorResponse(
                        status = HttpStatus.UNAUTHORIZED.value(),
                        error = "Unauthorized",
                        message = "User not authenticated"
                    )
                )

        val user = authDao.fetchByUsername(username).firstOrNull()
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(
                    ErrorResponse(
                        status = HttpStatus.NOT_FOUND.value(),
                        error = "Not Found",
                        message = "User not found"
                    )
                )

        if (!passwordEncoder.matches(request.oldPassword, user.password)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(
                    ErrorResponse(
                        status = HttpStatus.BAD_REQUEST.value(),
                        error = "Bad Request",
                        message = "Old password is incorrect"
                    )
                )
        }

        val encodedNewPassword = passwordEncoder.encode(request.newPassword)
        authDao.updatePassword(user.id!!, encodedNewPassword)

        return ResponseEntity.ok(mapOf("message" to "Password changed successfully"))
    }

    @PostMapping("/change/data")
    fun changeData(@RequestBody request: ChangeDataRequest): ResponseEntity<*> {
        val authentication: Authentication? = SecurityContextHolder.getContext().authentication
        val username = authentication?.name
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(
                    ErrorResponse(
                        status = HttpStatus.UNAUTHORIZED.value(),
                        error = "Unauthorized",
                        message = "User not authenticated"
                    )
                )

        val user = authDao.fetchByUsername(username).firstOrNull()
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(
                    ErrorResponse(
                        status = HttpStatus.NOT_FOUND.value(),
                        error = "Not Found",
                        message = "User not found"
                    )
                )

        if (request.email != null) {
            val existingUser = authDao.fetchByEmail(request.email).firstOrNull()
            if (existingUser != null && existingUser.id != user.id) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(
                        ErrorResponse(
                            status = HttpStatus.CONFLICT.value(),
                            error = "Conflict",
                            message = "Email already exists"
                        )
                    )
            }
        }

        authDao.updateUser(user.id!!, request.email)

        return ResponseEntity.ok(mapOf("message" to "User data updated successfully"))
    }

    @DeleteMapping("/delete")
    fun delete(): ResponseEntity<*> {
        val authentication: Authentication? = SecurityContextHolder.getContext().authentication
        val username = authentication?.name
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(
                    ErrorResponse(
                        status = HttpStatus.UNAUTHORIZED.value(),
                        error = "Unauthorized",
                        message = "User not authenticated"
                    )
                )

        val user = authDao.fetchByUsername(username).firstOrNull()
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(
                    ErrorResponse(
                        status = HttpStatus.NOT_FOUND.value(),
                        error = "Not Found",
                        message = "User not found"
                    )
                )

        authDao.deleteUser(user.id!!)
        SecurityContextHolder.clearContext()

        return ResponseEntity.ok(mapOf("message" to "User deleted successfully"))
    }

    @GetMapping("/get-by-token")
    fun getByToken(@RequestHeader(TOKEN) token: String): ResponseEntity<*> {
        val username = jwtTokenProvider.getUsernameFromToken(token)

        println(username)

        val userData = authDao.fetchByUsername(username).firstOrNull()
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND)

        println(userData)
        return ResponseEntity.ok(userData.toDto())
    }
}