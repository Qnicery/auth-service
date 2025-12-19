package org.example.auth.model

import java.time.LocalDateTime

data class User(
    val id: Long? = null,
    val username: String,
    val password: String,
    val email: String,
    val createdAt: LocalDateTime? = null,
    val updatedAt: LocalDateTime? = null
)

