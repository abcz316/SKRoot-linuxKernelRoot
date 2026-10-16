package com.android.apksig.internal.compat;

/**
 * Represents a supplier of {@code int}-valued results.  This is the
 * {@code int}-producing primitive specialization of {@link SupplierCompat}.
 *
 * <p>There is no requirement that a distinct result be returned each
 * time the supplier is invoked.
 *
 * @see SupplierCompat
 */
@FunctionalInterface
public interface IntSupplierCompat {

    /**
     * Gets a result.
     *
     * @return a result
     */
    int getAsInt();
}
