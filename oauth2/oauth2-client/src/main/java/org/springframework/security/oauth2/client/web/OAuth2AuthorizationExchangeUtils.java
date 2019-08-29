/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * Utility methods for OAuth 2.0 Authorization Exchange(Request and Response).
 *
 * @author Tadaya Tsuyukubo
 * @since 5.2
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationResponse
 */
public final class OAuth2AuthorizationExchangeUtils {

	private OAuth2AuthorizationExchangeUtils() {
	}

	/**
	 * Verify authorization response is appropriate for redirect_uri in authorization request.
	 *
	 * @param authRequest oauth2 authorization request
	 * @param authResponse oauth2 authorization response
	 * @return {@code true} if response has valid redirect_uri
	 */
	public static boolean isValidRedirectUri(OAuth2AuthorizationRequest authRequest,
			OAuth2AuthorizationResponse authResponse) {
		String authResponseRedirectUri = authResponse.getRedirectUri();
		MultiValueMap<String, String> authResponseParams = UriComponentsBuilder
				.fromUriString(authResponseRedirectUri).build().getQueryParams();

		return isValidRedirectUri(authRequest.getRedirectUri(), authResponseRedirectUri,
				authResponseParams);
	}

	public static boolean isValidRedirectUri(String authRequestRedirectUri, String authResponseRedirectUri,
			MultiValueMap<String, String> authResponseParams) {

		// simple check first. If they match, no query parameters exist in redirect uri
		if (authRequestRedirectUri.equals(authResponseRedirectUri)) {
			return true;
		}

		URI requestRedirectUri = URI.create(authRequestRedirectUri);
		String requestRedirectUrl = UrlUtils.buildFullRequestUrl(
				requestRedirectUri.getScheme(), requestRedirectUri.getHost(),
				requestRedirectUri.getPort() == -1 ? 80 : requestRedirectUri.getPort(),
				requestRedirectUri.getPath(), null);

		URI responseRedirectUri = URI.create(authResponseRedirectUri);
		String responseRedirectUrl = UrlUtils.buildFullRequestUrl(
				responseRedirectUri.getScheme(), responseRedirectUri.getHost(),
				responseRedirectUri.getPort() == -1 ? 80 : responseRedirectUri.getPort(),
				responseRedirectUri.getPath(), null);

		// check the non query param part of the uri
		if (!requestRedirectUrl.equals(responseRedirectUrl)) {
			return false;
		}

		MultiValueMap<String, String> authRequestParams = UriComponentsBuilder.fromUri(requestRedirectUri).build().getQueryParams();

		// query params in request needs to exist in response query params
		for (Map.Entry<String, List<String>> entry : authRequestParams.entrySet()) {
			String redirectParamKey = entry.getKey();
			List<String> redirectParamValues = entry.getValue();
			List<String> values = authResponseParams.get(redirectParamKey);
			if (values == null) {
				return false;
			}
			if (!values.containsAll(redirectParamValues)) {
				return false;
			}
		}
		return true;

	}

}
