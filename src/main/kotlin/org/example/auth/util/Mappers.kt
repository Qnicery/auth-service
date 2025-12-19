package org.example.auth.util

import org.example.auth.dto.response.UserDataResponse
import org.example.auth.jooq.tables.pojos.Users

fun Users.toDto() = UserDataResponse(
    id = id,
    username = username,
    email = email,
    createdAt = createdAt,
    updatedAt = updatedAt
)