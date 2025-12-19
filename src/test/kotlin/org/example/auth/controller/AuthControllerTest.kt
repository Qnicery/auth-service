package org.example.auth.controller

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.example.auth.dao.AuthDao
import org.example.auth.dto.request.*
import org.example.auth.jooq.tables.pojos.Users
import org.example.auth.model.User
import org.example.auth.security.JwtTokenProvider
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import java.time.LocalDateTime

class AuthControllerTest {

    private lateinit var passwordEncoder: PasswordEncoder
    private lateinit var jwtTokenProvider: JwtTokenProvider
    private lateinit var authDao: AuthDao
    private lateinit var authController: AuthController

    @BeforeEach
    fun setUp() {
        passwordEncoder = mockk()
        jwtTokenProvider = mockk()
        authDao = mockk()
        authController = AuthController(passwordEncoder, jwtTokenProvider, authDao)
    }

    @Test
    fun `register should return token when user is created successfully`() {
        val request = RegisterRequest("testuser", "test@example.com", "password123")
        val encodedPassword = "encodedPassword"
        val token = "test-token"
        val user = User(
            id = 1L,
            username = request.username,
            password = encodedPassword,
            email = request.email,
            createdAt = LocalDateTime.now(),
            updatedAt = LocalDateTime.now()
        )

        every { authDao.fetchByUsername(request.username) } returns emptyList()
        every { authDao.fetchByEmail(request.email) } returns emptyList()
        every { passwordEncoder.encode(request.password) } returns encodedPassword
        every { authDao.createUser(any()) } returns user
        every { jwtTokenProvider.createToken(request.username) } returns token

        val response = authController.register(request)

        assertEquals(HttpStatus.OK, response.statusCode)
        assertNotNull(response.body)
        verify { authDao.fetchByUsername(request.username) }
        verify { authDao.fetchByEmail(request.email) }
        verify { passwordEncoder.encode(request.password) }
        verify { authDao.createUser(any()) }
        verify { jwtTokenProvider.createToken(request.username) }
    }

    @Test
    fun `register should return conflict when username already exists`() {
        val now = LocalDateTime.now()
        val request = RegisterRequest("testuser", "test@example.com", "password123")
        val existingUser = Users(1L, request.username, "pass", "email", now, now)

        every { authDao.fetchByUsername(request.username) } returns listOf(existingUser)

        val response = authController.register(request)

        assertEquals(HttpStatus.CONFLICT, response.statusCode)
        verify { authDao.fetchByUsername(request.username) }
        verify(exactly = 0) { authDao.createUser(any()) }
    }

    @Test
    fun `register should return conflict when email already exists`() {
        val now = LocalDateTime.now()
        val request = RegisterRequest("testuser", "test@example.com", "password123")
        val existingUser = Users(1L, "other", "pass", request.email, now, now)

        every { authDao.fetchByUsername(request.username) } returns emptyList()
        every { authDao.fetchByEmail(request.email) } returns listOf(existingUser)

        val response = authController.register(request)

        assertEquals(HttpStatus.CONFLICT, response.statusCode)
        verify { authDao.fetchByUsername(request.username) }
        verify { authDao.fetchByEmail(request.email) }
        verify(exactly = 0) { authDao.createUser(any()) }
    }

    @Test
    fun `login should return token when credentials are valid`() {
        val now = LocalDateTime.now()
        val request = LoginRequest("testuser", "password123")
        val encodedPassword = "encodedPassword"
        val token = "test-token"
        val user = Users(1L, request.username,  encodedPassword, "test@example.com", now, now)

        every { authDao.fetchByUsername(request.username) } returns listOf(user)
        every { passwordEncoder.matches(request.password, encodedPassword) } returns true
        every { jwtTokenProvider.createToken(request.username) } returns token

        val response = authController.login(request)

        assertEquals(HttpStatus.OK, response.statusCode)
        verify { authDao.fetchByUsername(request.username) }
        verify { passwordEncoder.matches(request.password, encodedPassword) }
        verify { jwtTokenProvider.createToken(request.username) }
    }

    @Test
    fun `login should return unauthorized when user not found`() {
        val request = LoginRequest("testuser", "password123")

        every { authDao.fetchByUsername(request.username) } returns emptyList()

        val response = authController.login(request)

        assertEquals(HttpStatus.UNAUTHORIZED, response.statusCode)
        verify { authDao.fetchByUsername(request.username) }
        verify(exactly = 0) { jwtTokenProvider.createToken(any()) }
    }

    @Test
    fun `login should return unauthorized when password is incorrect`() {
        val request = LoginRequest("testuser", "wrongpassword")
        val encodedPassword = "encodedPassword"
        val now = LocalDateTime.now()
        val user = Users(1L, request.username,  encodedPassword, "test@example.com", now, now)

        every { authDao.fetchByUsername(request.username) } returns listOf(user)
        every { passwordEncoder.matches(request.password, encodedPassword) } returns false

        val response = authController.login(request)

        assertEquals(HttpStatus.UNAUTHORIZED, response.statusCode)
        verify { authDao.fetchByUsername(request.username) }
        verify { passwordEncoder.matches(request.password, encodedPassword) }
        verify(exactly = 0) { jwtTokenProvider.createToken(any()) }
    }

    @Test
    fun `changePassword should return success when password is changed`() {
        val request = ChangePasswordRequest("oldPassword", "newPassword")
        val username = "testuser"
        val encodedOldPassword = "encodedOldPassword"
        val encodedNewPassword = "encodedNewPassword"
        val now = LocalDateTime.now()
        val user = Users(1L, username,  encodedOldPassword, "test@example.com", now, now)

        val authentication = mockk<Authentication>()
        val securityContext = mockk<SecurityContext>()

        every { authentication.name } returns username
        every { securityContext.authentication } returns authentication
        SecurityContextHolder.setContext(securityContext)

        every { authDao.fetchByUsername(username) } returns listOf(user)
        every { passwordEncoder.matches(request.oldPassword, encodedOldPassword) } returns true
        every { passwordEncoder.encode(request.newPassword) } returns encodedNewPassword
        every { authDao.updatePassword(user.id!!, encodedNewPassword) } returns Unit

        val response = authController.changePassword(request)

        assertEquals(HttpStatus.OK, response.statusCode)
        verify { authDao.fetchByUsername(username) }
        verify { passwordEncoder.matches(request.oldPassword, encodedOldPassword) }
        verify { passwordEncoder.encode(request.newPassword) }
        verify { authDao.updatePassword(user.id!!, encodedNewPassword) }

        SecurityContextHolder.clearContext()
    }

    @Test
    fun `getByToken should return user data when token is valid`() {
        val token = "valid-token"
        val username = "testuser"
        val user = Users(
            1L,
            username,
            "password",
            "test@example.com",
            LocalDateTime.now(),
            LocalDateTime.now()
        )

        every { jwtTokenProvider.getUsernameFromToken(token) } returns username
        every { authDao.fetchByUsername(username) } returns listOf(user)

        val response = authController.getByToken(token)

        assertEquals(HttpStatus.OK, response.statusCode)
        assertNotNull(response.body)
        verify { jwtTokenProvider.getUsernameFromToken(token) }
        verify { authDao.fetchByUsername(username) }
    }
}

