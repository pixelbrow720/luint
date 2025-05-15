"""
Cache Manager for LUINT.
Provides caching functionality to avoid redundant requests and computations.
"""
import os
import time
import json
import hashlib
import pickle
from typing import Any, Dict, Optional, List, Union, Tuple
import threading

from luint.utils.logger import get_logger

logger = get_logger()


class CacheManager:
    """
    Manages caching of data to improve performance and reduce API calls.
    """
    
    def __init__(self, cache_dir: Optional[str] = None, 
                 default_ttl: int = 3600, 
                 enabled: bool = True):
        """
        Initialize the cache manager.
        
        Args:
            cache_dir (str, optional): Directory to store cache files. 
                If None, uses a default directory in the user's home directory.
            default_ttl (int): Default time-to-live for cache entries in seconds (default: 1 hour)
            enabled (bool): Whether caching is enabled
        """
        self.enabled = enabled
        self.default_ttl = default_ttl
        self.memory_cache = {}
        self.last_access = {}
        self.ttl_values = {}
        self.lock = threading.RLock()
        
        if cache_dir is None:
            user_home = os.path.expanduser("~")
            cache_dir = os.path.join(user_home, ".luint", "cache")
        
        self.cache_dir = cache_dir
        
        # Create cache directory if it doesn't exist
        if self.enabled and not os.path.exists(self.cache_dir):
            try:
                os.makedirs(self.cache_dir)
                logger.debug(f"Created cache directory: {self.cache_dir}")
            except OSError as e:
                logger.warning(f"Failed to create cache directory: {e}")
                self.enabled = False
    
    def _get_cache_key(self, key: str, namespace: str = "default") -> str:
        """
        Generate a cache key from a key string and namespace.
        
        Args:
            key (str): Original key
            namespace (str): Namespace to group cache entries
            
        Returns:
            str: Hashed cache key
        """
        combined_key = f"{namespace}:{key}"
        return hashlib.md5(combined_key.encode()).hexdigest()
    
    def _get_cache_path(self, cache_key: str) -> str:
        """
        Get the file path for a cache key.
        
        Args:
            cache_key (str): Cache key
            
        Returns:
            str: Path to the cache file
        """
        return os.path.join(self.cache_dir, f"{cache_key}.cache")
    
    def get(self, key: str, namespace: str = "default") -> Optional[Any]:
        """
        Get a value from the cache.
        
        Args:
            key (str): Cache key
            namespace (str): Cache namespace
            
        Returns:
            Any or None: Cached value or None if not found or expired
        """
        if not self.enabled:
            return None
            
        with self.lock:
            cache_key = self._get_cache_key(key, namespace)
            
            # Check memory cache first
            if cache_key in self.memory_cache:
                # Check if expired
                ttl = self.ttl_values.get(cache_key, self.default_ttl)
                last_access = self.last_access.get(cache_key, 0)
                
                if time.time() - last_access <= ttl:
                    self.last_access[cache_key] = time.time()
                    return self.memory_cache[cache_key]
                else:
                    # Expired, remove from memory cache
                    del self.memory_cache[cache_key]
                    if cache_key in self.ttl_values:
                        del self.ttl_values[cache_key]
                    if cache_key in self.last_access:
                        del self.last_access[cache_key]
            
            # Check file cache
            cache_path = self._get_cache_path(cache_key)
            if os.path.exists(cache_path):
                try:
                    with open(cache_path, 'rb') as f:
                        cache_data = pickle.load(f)
                        
                    timestamp = cache_data.get('timestamp', 0)
                    ttl = cache_data.get('ttl', self.default_ttl)
                    
                    # Check if expired
                    if time.time() - timestamp <= ttl:
                        value = cache_data.get('value')
                        
                        # Store in memory cache for faster access next time
                        self.memory_cache[cache_key] = value
                        self.ttl_values[cache_key] = ttl
                        self.last_access[cache_key] = time.time()
                        
                        return value
                    else:
                        # Expired, delete the file
                        try:
                            os.remove(cache_path)
                        except OSError:
                            pass
                except (OSError, pickle.PickleError) as e:
                    logger.debug(f"Error reading cache file: {e}")
            
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None, namespace: str = "default") -> bool:
        """
        Set a value in the cache.
        
        Args:
            key (str): Cache key
            value (Any): Value to cache
            ttl (int, optional): Time-to-live in seconds. If None, uses default TTL.
            namespace (str): Cache namespace
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled:
            return False
            
        ttl = ttl if ttl is not None else self.default_ttl
        
        with self.lock:
            cache_key = self._get_cache_key(key, namespace)
            
            # Store in memory cache
            self.memory_cache[cache_key] = value
            self.ttl_values[cache_key] = ttl
            self.last_access[cache_key] = time.time()
            
            # Store in file cache
            cache_path = self._get_cache_path(cache_key)
            try:
                cache_data = {
                    'timestamp': time.time(),
                    'ttl': ttl,
                    'value': value,
                    'namespace': namespace,
                    'key': key
                }
                
                with open(cache_path, 'wb') as f:
                    pickle.dump(cache_data, f)
                
                return True
            except (OSError, pickle.PickleError) as e:
                logger.warning(f"Error writing to cache file: {e}")
                return False
    
    def delete(self, key: str, namespace: str = "default") -> bool:
        """
        Delete a value from the cache.
        
        Args:
            key (str): Cache key
            namespace (str): Cache namespace
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled:
            return False
            
        with self.lock:
            cache_key = self._get_cache_key(key, namespace)
            
            # Remove from memory cache
            if cache_key in self.memory_cache:
                del self.memory_cache[cache_key]
            if cache_key in self.ttl_values:
                del self.ttl_values[cache_key]
            if cache_key in self.last_access:
                del self.last_access[cache_key]
            
            # Remove from file cache
            cache_path = self._get_cache_path(cache_key)
            if os.path.exists(cache_path):
                try:
                    os.remove(cache_path)
                    return True
                except OSError as e:
                    logger.warning(f"Error deleting cache file: {e}")
                    return False
            
            return True
    
    def clear(self, namespace: Optional[str] = None) -> bool:
        """
        Clear the cache, optionally for a specific namespace.
        
        Args:
            namespace (str, optional): Cache namespace to clear. If None, clears all caches.
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled:
            return False
            
        with self.lock:
            if namespace is None:
                # Clear all cache
                self.memory_cache = {}
                self.ttl_values = {}
                self.last_access = {}
                
                # Clear all cache files
                try:
                    if os.path.exists(self.cache_dir):
                        for filename in os.listdir(self.cache_dir):
                            if filename.endswith('.cache'):
                                os.remove(os.path.join(self.cache_dir, filename))
                    return True
                except OSError as e:
                    logger.warning(f"Error clearing cache directory: {e}")
                    return False
            else:
                # Clear only the specified namespace
                prefix = f"{namespace}:"
                
                # Clear from memory cache
                keys_to_delete = []
                for cache_key in list(self.memory_cache.keys()):
                    raw_key = self._get_raw_key(cache_key)
                    if raw_key.startswith(prefix):
                        keys_to_delete.append(cache_key)
                
                for key in keys_to_delete:
                    if key in self.memory_cache:
                        del self.memory_cache[key]
                    if key in self.ttl_values:
                        del self.ttl_values[key]
                    if key in self.last_access:
                        del self.last_access[key]
                
                # Clear from file cache
                try:
                    for cache_key in keys_to_delete:
                        cache_path = self._get_cache_path(cache_key)
                        if os.path.exists(cache_path):
                            os.remove(cache_path)
                    return True
                except OSError as e:
                    logger.warning(f"Error clearing namespace from cache: {e}")
                    return False
    
    def _get_raw_key(self, cache_key: str) -> str:
        """
        Get the original key:namespace pair from a cache key (for internal use).
        
        Args:
            cache_key (str): Hashed cache key
            
        Returns:
            str: Original key:namespace string or empty string if not found
        """
        # This is an approximation as hash functions are one-way
        # We'll iterate through our in-memory cache to find this
        for original_key, original_namespace in self._get_all_keys_namespaces():
            if self._get_cache_key(original_key, original_namespace) == cache_key:
                return f"{original_namespace}:{original_key}"
        return ""
    
    def _get_all_keys_namespaces(self) -> List[Tuple[str, str]]:
        """
        Get all key-namespace pairs by scanning cache files.
        
        Returns:
            list: List of (key, namespace) tuples
        """
        pairs = []
        if os.path.exists(self.cache_dir):
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.cache'):
                    try:
                        with open(os.path.join(self.cache_dir, filename), 'rb') as f:
                            cache_data = pickle.load(f)
                            if 'namespace' in cache_data and 'key' in cache_data:
                                pairs.append((cache_data['key'], cache_data['namespace']))
                    except (OSError, pickle.PickleError):
                        continue
        return pairs
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the cache.
        
        Returns:
            dict: Cache statistics
        """
        with self.lock:
            file_count = 0
            file_size = 0
            
            if os.path.exists(self.cache_dir):
                for filename in os.listdir(self.cache_dir):
                    if filename.endswith('.cache'):
                        file_path = os.path.join(self.cache_dir, filename)
                        file_count += 1
                        try:
                            file_size += os.path.getsize(file_path)
                        except OSError:
                            pass
            
            return {
                'enabled': self.enabled,
                'memory_entries': len(self.memory_cache),
                'file_entries': file_count,
                'file_size_bytes': file_size,
                'cache_dir': self.cache_dir,
                'default_ttl': self.default_ttl
            }
    
    def invalidate_old_entries(self, max_age: Optional[int] = None) -> int:
        """
        Invalidate all cache entries older than the specified age.
        
        Args:
            max_age (int, optional): Maximum age in seconds. If None, uses default TTL.
            
        Returns:
            int: Number of entries invalidated
        """
        if not self.enabled:
            return 0
            
        max_age = max_age if max_age is not None else self.default_ttl
        invalidated_count = 0
        
        with self.lock:
            now = time.time()
            
            # Check memory cache
            memory_keys_to_delete = []
            for cache_key, last_access in self.last_access.items():
                if now - last_access > max_age:
                    memory_keys_to_delete.append(cache_key)
            
            for key in memory_keys_to_delete:
                if key in self.memory_cache:
                    del self.memory_cache[key]
                if key in self.ttl_values:
                    del self.ttl_values[key]
                if key in self.last_access:
                    del self.last_access[key]
                invalidated_count += 1
            
            # Check file cache
            if os.path.exists(self.cache_dir):
                for filename in os.listdir(self.cache_dir):
                    if filename.endswith('.cache'):
                        file_path = os.path.join(self.cache_dir, filename)
                        try:
                            # Check file modification time
                            if now - os.path.getmtime(file_path) > max_age:
                                os.remove(file_path)
                                invalidated_count += 1
                        except OSError:
                            pass
        
        return invalidated_count
