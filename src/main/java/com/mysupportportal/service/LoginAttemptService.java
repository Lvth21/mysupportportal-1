package com.mysupportportal.service;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.util.concurrent.ExecutionException;

import org.springframework.stereotype.Service;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

@Service
public class LoginAttemptService {

	private static final int MAXIMUM_NUMBER_OF_ATTEMPTS = 5;
	private static final int ATTEMPT_INCREMENT = 1;
	private LoadingCache<String, Integer> loginAttemptCache;

	/*
	 * This code creates a new instance of the LoginAttemptService class. Inside the
	 * constructor, it creates a new cache object called loginAttemptCache using the
	 * Guava library's CacheBuilder class. The loginAttemptCache is an in-memory
	 * cache that holds a limited number of key-value pairs.
	 * 
	 * The expireAfterWrite method is used to set the cache's expiration time, which
	 * is 15 minutes in this case. The maximumSize(100) is the maximum number of
	 * users that can be inserted into the cache at the same time. If the number of
	 * users in the cache exceeds this limit, the cache will automatically remove
	 * the oldest entries to make room for new ones.
	 * 
	 * The build method is used to construct the actual cache and it takes a
	 * CacheLoader object as an argument. The CacheLoader is responsible for loading
	 * a value for a given key when the key is not present in the cache. In this
	 * case, if the key is not present in the cache, it will return 0.
	 * 
	 * 
	 * ************************************************* in dept
	 * This code creates an	 * instance of the CacheLoader class that defines the behavior 
	 * of loading a value for a given key when the key is not present in the cache. The
	 * CacheLoader is a generic class that takes two arguments, the first one is the
	 * type of the key and the second one is the type of the value.
	 * 
	 * In this case, the key is of type String and the value is of type Integer. The
	 * load method is an abstract method that needs to be overridden, it takes the
	 * key as an argument and returns the value that should be associated with that
	 * key.
	 * 
	 * In this specific example, the load method is returning 0 for any key that is
	 * not found in the cache. So, if a user tries to log in and their IP address is
	 * not present in the cache, the loginAttemptCache will return 0 for that IP
	 * address
	 * ********************************************************
	 * 
	 * 
	 */

	// initialize the cache
	public LoginAttemptService() {// maximumSize(100) is the maximum number of users that are inserted in the
									// cache at same time.
		super(); // it creates a new cache object
		loginAttemptCache = CacheBuilder.newBuilder().expireAfterWrite(15, MINUTES).maximumSize(100)
				.build(new CacheLoader<String, Integer>() {// **** in dept
					public Integer load(String key) {
						return 0;
					}
				});
	}

	// remove the user from the cache
	public void evictUserFromLoginAttemptCache(String username) {
		loginAttemptCache.invalidate(username);
	}

	public void addUserToLoginAttemptCache(String username) {
		int attempts = 0;
		try {
			attempts = ATTEMPT_INCREMENT + loginAttemptCache.get(username);
		} catch (ExecutionException e) {
			e.printStackTrace();
		}
		loginAttemptCache.put(username, attempts);
	}

	public boolean hasExceededMaxAttempts(String username) {
		try {
			return loginAttemptCache.get(username) >= MAXIMUM_NUMBER_OF_ATTEMPTS;
		} catch (ExecutionException e) {
			e.printStackTrace();
		}
		return false;
	}
}
