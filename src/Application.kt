package com.omnigate

import com.auth0.jwk.JwkProvider
import com.auth0.jwk.UrlJwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.interfaces.RSAKeyProvider
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import io.ktor.client.features.json.JacksonSerializer
import io.ktor.client.features.json.JsonFeature
import io.ktor.client.features.logging.LogLevel
import io.ktor.client.features.logging.Logging
import io.ktor.client.request.post
import io.ktor.features.ContentNegotiation
import io.ktor.gson.gson
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.server.netty.EngineMain
import io.ktor.util.KtorExperimentalAPI
import kotlinx.coroutines.runBlocking
import java.net.URL
import java.security.interfaces.RSAPublicKey


fun main(args: Array<String>): Unit = EngineMain.main(args)

@KtorExperimentalAPI
@Suppress("unused") // Referenced in application.conf
@kotlin.jvm.JvmOverloads
fun Application.module(testing: Boolean = false) {

    val json = JacksonSerializer {
    }
    val client = HttpClient(Apache) {
        install(JsonFeature) {
            serializer = json
        }
        install(Logging) {
            level = LogLevel.BODY
        }
        install(ContentNegotiation) {
            gson { }
        }
    }


    val omnigateBaseUrl = environment.config.property("omnigate.baseurl").getString()
    val gsBaseUrl = environment.config.property("gamesparks.baseurl").getString()
    val gsCredential = environment.config.property("gamesparks.credential").getString()
    val gsSecret = environment.config.property("gamesparks.apisecret").getString()
    val gsUserPassword = environment.config.property("gamesparks.userpassword").getString()

    lateinit var jwkProvider: JwkProvider
    runBlocking {
        val jwksUrl = URL("$omnigateBaseUrl/auth/jwks.json")
        jwkProvider = UrlJwkProvider(jwksUrl)

    }


    routing {
        get("/auth/gamesparks/gettoken") {
            /* VERIFY OMNIGATE JWT TOKEN */
            val keyProvider = object : RSAKeyProvider {
                override fun getPrivateKeyId() = null
                override fun getPrivateKey() = null
                override fun getPublicKeyById(keyId: String?): RSAPublicKey {
                    return jwkProvider[keyId].publicKey as RSAPublicKey
                }
            }

            val algo = Algorithm.RSA256(keyProvider)
            val jwt = call.request.headers["Authentication"]?.substringAfter("Bearer ")

            lateinit var decodedToken: DecodedJWT
            try {
                val verifier = JWT.require(algo)
                    .build()
                decodedToken = verifier.verify(jwt)
            } catch (e: JWTVerificationException) {
                println("JWT verification failed with error:")
                e.printStackTrace()
            }

            /* EXTRACT UUID FROM JWT TOKEN */
            val uuid = decodedToken.getClaim("sub").asString()
            if (uuid == null) call.respond(
                ErrorResponse(
                    1338002,
                    "UUID couldn't be extracted from JWT token"
                )
            )


            /* REGISTER A NEW GAMESPARKS USER OR TRY TO LOGIN IF THAT FAILS */
            val gsBaseEndpointUrl = "$gsBaseUrl/rs/$gsCredential/$gsSecret"
            val registrationUrl = "$gsBaseEndpointUrl/RegistrationRequest"

            var authToken: String? = null

            val registrationResponse: Json?
            try {
                registrationResponse = client.post<Json>(registrationUrl) {
                    body = json.write(
                        mapOf(
                            "@class" to ".RegistrationRequest",
                            "userName" to uuid,
                            "password" to gsUserPassword,
                            "displayName" to uuid
                        )
                    )
                }
                authToken = registrationResponse["authToken"] as String?
            } catch (e: Exception) {
                println("Registration failed with error:")
                e.printStackTrace()
            }

            val authenticationUrl = "$gsBaseEndpointUrl/AuthenticationRequest"
            val authenticationResponse: Json?
            try {
                authenticationResponse = client.post<Json>(authenticationUrl) {
                    body = json.write(
                        mapOf(
                            "@class" to ".AuthenticationRequest",
                            "userName" to uuid,
                            "password" to gsUserPassword
                        )
                    )
                }
                authToken = authenticationResponse["authToken"] as String?
            } catch (e: Exception) {
                println("Authentication failed with error:")
                e.printStackTrace()
            }

            if (authToken == null) call.respond(
                ErrorResponse(
                    1338001,
                    "Failed to authenticate with GameSparks"
                )
            )
            else call.respond(TokenResponse(authToken, uuid))
        }
    }
}

data class TokenResponse(val token: String, val userId: String)

data class ErrorResponse(val resultcode: Int, val resultmessage: String)

typealias Json = Map<String, Any>