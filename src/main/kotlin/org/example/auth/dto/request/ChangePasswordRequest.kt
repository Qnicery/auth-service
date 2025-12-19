package org.example.auth.dto.request

data class ChangePasswordRequest(val oldPassword: String, val newPassword: String)

