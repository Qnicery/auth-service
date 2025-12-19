package org.example.auth.dto.response

import java.time.LocalDateTime

data class UserDataResponse(
    val id: Long,
    val username: String,
    val email: String,
    val createdAt: LocalDateTime,
    val updatedAt: LocalDateTime
)