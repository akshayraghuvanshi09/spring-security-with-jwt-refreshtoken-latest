package com.springsecuritywithdb;

import java.util.HashMap;
import java.util.Map;

public class AppContext {
	private static ThreadLocal<Map<String, String>> contextData = new ThreadLocal<>();

	public enum Key {
		SESSION_ID, USER_ID, USER_EMAIL
	}

	public static String get(Key key) {
		return getContextMap().get(key.name());
	}

	public static String set(Key key, String value) {
		return getContextMap().put(key.name(), value);
	}

	public static String get(String key) {
		return getContextMap().get(key);
	}

	public static String set(String key, String value) {
		return getContextMap().put(key, value);
	}

	public static Map<String, String> getContextMap() {
		if (contextData.get() == null) {
			contextData.set(new HashMap<>());
		}
		return contextData.get();
	}

}
