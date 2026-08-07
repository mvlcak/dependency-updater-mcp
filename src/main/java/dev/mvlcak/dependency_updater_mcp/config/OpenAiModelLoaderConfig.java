package dev.mvlcak.dependency_updater_mcp.config;

import com.embabel.agent.config.models.openai.OpenAiModelDefinitions;
import com.embabel.agent.config.models.openai.OpenAiModelLoader;
import com.embabel.common.ai.autoconfig.LlmAutoConfigMetadataLoader;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Embabel loads models/openai-models.yml with a bare Jackson ObjectMapper, so ${...}
 * placeholders in that file are never expanded. Replace the default loader with one that
 * runs the YAML through the Spring Environment first, which lets the Azure deployment name
 * come from env.properties / environment variables instead of being hard-coded.
 */
@Configuration(proxyBeanMethods = false)
public class OpenAiModelLoaderConfig {

    private static final String CONFIG_PATH = "classpath:models/openai-models.yml";

    @Bean
    LlmAutoConfigMetadataLoader<OpenAiModelDefinitions> openAiModelLoader(
            Environment environment,
            ResourceLoader resourceLoader) {
        return new OpenAiModelLoader(new PlaceholderResolvingResourceLoader(resourceLoader, environment), CONFIG_PATH);
    }

    private record PlaceholderResolvingResourceLoader(ResourceLoader delegate, Environment environment)
            implements ResourceLoader {

        @Override
        public Resource getResource(String location) {
            Resource raw = delegate.getResource(location);
            if (!raw.exists()) {
                return raw;
            }
            try (InputStream in = raw.getInputStream()) {
                String yaml = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                String resolved = environment.resolveRequiredPlaceholders(yaml);
                return new ByteArrayResource(resolved.getBytes(StandardCharsets.UTF_8), location);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to read " + location, e);
            }
        }

        @Override
        public ClassLoader getClassLoader() {
            return delegate.getClassLoader();
        }
    }
}