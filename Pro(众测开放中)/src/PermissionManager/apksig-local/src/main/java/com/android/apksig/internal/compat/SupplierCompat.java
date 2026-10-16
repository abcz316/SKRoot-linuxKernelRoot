package com.android.apksig.internal.compat;

/**
 * Represents a supplier of results.
 *
 * <p>There is no requirement that a new or distinct result be returned each
 * time the supplier is invoked.
 *
 * @param <T> the type of results supplied by this supplier
 */
@FunctionalInterface
public interface SupplierCompat<T> {

    /**
     * Gets a result.
     *
     * @return a result
     */
    T get();
}
