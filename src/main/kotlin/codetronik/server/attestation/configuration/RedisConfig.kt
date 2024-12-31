package codetronik.server.attestation.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.serializer.StringRedisSerializer

@Configuration
class RedisConfig {
	@Bean
	fun redisConnectionFactory(): LettuceConnectionFactory {
		return LettuceConnectionFactory("localhost", 6379)  // Redis 서버 주소와 포트
	}

	@Bean
	fun redisTemplate(): RedisTemplate<String, Any> {
		val redisTemplate = RedisTemplate<String, Any>()
		redisTemplate.connectionFactory = redisConnectionFactory()  // 연결 팩토리 설정
		redisTemplate.keySerializer = StringRedisSerializer()  // Redis의 키는 String으로 설정
		redisTemplate.valueSerializer = StringRedisSerializer()  // Redis의 값도 String으로 설정
		return redisTemplate
	}
}