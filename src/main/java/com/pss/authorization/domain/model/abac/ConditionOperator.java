package com.pss.authorization.domain.model.abac;

/**
 * Condition operators for ABAC policy evaluation.
 */
public enum ConditionOperator {

    // Equality
    EQUALS,
    NOT_EQUALS,

    // Comparison (for numbers/dates)
    GREATER_THAN,
    GREATER_THAN_OR_EQUALS,
    LESS_THAN,
    LESS_THAN_OR_EQUALS,

    // String operations
    CONTAINS,
    NOT_CONTAINS,
    STARTS_WITH,
    ENDS_WITH,
    MATCHES_REGEX,

    // Collection operations
    IN,
    NOT_IN,
    CONTAINS_ALL,
    CONTAINS_ANY,

    // Null checks
    IS_NULL,
    IS_NOT_NULL,

    // Range
    BETWEEN,

    // IP operations
    IP_IN_RANGE,
    IP_IN_CIDR
}
