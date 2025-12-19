package org.example.auth.dao

import org.example.auth.jooq.Tables.USERS
import org.example.auth.jooq.tables.daos.UsersDao
import org.example.auth.model.User
import org.jooq.DSLContext
import org.springframework.stereotype.Repository
import java.time.LocalDateTime

@Repository
class AuthDao(
    private val dsl: DSLContext
) : UsersDao(dsl.configuration()) {

    fun createUser(user: User): User {
        val now = LocalDateTime.now()
        val record = dsl.insertInto(USERS)
            .set(USERS.USERNAME, user.username)
            .set(USERS.PASSWORD, user.password)
            .set(USERS.EMAIL, user.email)
            .set(USERS.CREATED_AT, now)
            .set(USERS.UPDATED_AT, now)
            .returning()
            .fetchOne()

        val id = record?.get(USERS.ID)


        return user.copy(id = id, createdAt = now, updatedAt = now)
    }

    fun updatePassword(userId: Long, newPassword: String) {
        dsl.update(USERS)
            .set(USERS.PASSWORD, newPassword)
            .set(USERS.UPDATED_AT, LocalDateTime.now())
            .where(USERS.ID.eq(userId))
            .execute()
    }

    fun updateEmail(userId: Long, newEmail: String) {
        dsl.update(USERS)
            .set(USERS.EMAIL, newEmail)
            .set(USERS.UPDATED_AT, LocalDateTime.now())
            .where(USERS.ID.eq(userId))
            .execute()
    }

    fun updateUser(userId: Long, email: String?) {
        val update = dsl.update(USERS)
            .set(USERS.UPDATED_AT, LocalDateTime.now())

        if (email != null) {
            update.set(USERS.EMAIL, email)
        }

        update.where(USERS.ID.eq(userId))
            .execute()
    }

    fun deleteUser(userId: Long) {
        dsl.deleteFrom(USERS)
            .where(USERS.ID.eq(userId))
            .execute()
    }
}