import math

# ---------------------- HELPER FUNCTIONS FOR WEIGHTED CIRCULAR DISTANCE MODEL ----------------------

# Calculates the angular position of the current value (x) based on whether it's a weekend or not
def angular_pos_curr_val(x: int, weekend_flag: bool) -> float:
    if weekend_flag:
        return (2 * math.pi * x) / 7
    else:
        return (2 * math.pi * x) / 24 # Assuming x is the hour of the day (0-23)

# Identifies the bins that have values greater than 0 and calculates their angular positions
def angular_pos_bin_i(bins: list[int], weekend_flag: bool) -> list[tuple[int, float]]:
    computed_bins = []
    for b in range(len(bins)):
        if bins[b] > 0:
            computed_bins.append((b, angular_pos_curr_val(b, weekend_flag)))

    return computed_bins
    
# Computes the cosine of the difference between the current value's angular position and each bin's angular position
def cos_pos_currVal_minus_binI(x: int, bins: list[int], weekend_flag: bool) -> list[tuple[int, float]]:
    curr_val = angular_pos_curr_val(x, weekend_flag)
    bin_i = angular_pos_bin_i(bins, weekend_flag)

    return [(b, math.cos(curr_val - bin_i_val)) for b, bin_i_val in bin_i]

# Computes the weighted sum of the cosine values, where the weights are the counts in the bins
def weighted_sum(bins: list[int], computed_cos: list[tuple[int, float]]) -> float:
    total = 0.0
    for b, cos_val in computed_cos:
        total += bins[b] * cos_val
    return total

# Computes the total weight (sum of all bins) to normalize the weighted sum of cosine values
def total_weight(bins: list[int]) -> float:
    return sum(bins)

# ---------------------- MAIN FUNCTIONS FOR WEIGHTED CIRCULAR DISTANCE MODEL ----------------------

# Computes the weighted circular distance based on the current value, the bins, and whether it's a weekend or not
def weighted_circular_distance(x: int, bins: list[int], weekend_flag: bool) -> float:
    cyclic_distance = 1/2 * ((weighted_sum(bins, cos_pos_currVal_minus_binI(x, bins, weekend_flag)) / total_weight(bins)) + 1)
    return cyclic_distance

# Combines the weighted circular distance with a sigmoid transformation to produce a hybrid score
def hybrid_scoring(x: int, bins: list[int], weekend_flag: bool) -> float:
    return 1 - weighted_circular_distance(x, bins, weekend_flag)

