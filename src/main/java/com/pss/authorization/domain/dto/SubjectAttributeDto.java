package com.pss.authorization.domain.dto;

import java.time.Instant;

/**
 * Cacheable DTO for SubjectAttributes avoiding Jackson infinite recursion
 * issues.
 */
public record SubjectAttributeDto(
        String name,
        String value,
        Instant validFrom,
        Instant validUntil) {
    /**
     * Checks if this attribute is currently valid.
     */
    public boolean isValid() {
        Instant now = Instant.now();
        var afterStart = validFrom == null || !now.isBefore(validFrom);
        var beforeEnd = validUntil == null || now.isBefore(validUntil);
        return afterStart && beforeEnd;
    }
}
