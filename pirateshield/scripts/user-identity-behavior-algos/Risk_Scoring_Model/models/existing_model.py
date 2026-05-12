from abc import ABC
import math

# To represent the existing risk score model
class RiskScoreModel(ABC):
    def __init__(self, k: float = 1.0, mu: float = 2.0):
        """
        Parameters:
            k (float): The steepness of the sigmoid curve. Default is 1.0.
            mu (float): The midpoint of the sigmoid curve. Default is 2.0.
        """
        self.k = k
        self.mu = mu

    # Calculates how many standard deviations a value is from the mean
    def z_score(self, value: float, mean: float, std_dev: float) -> float:
        if std_dev == 0:
            raise ValueError("Standard deviation cannot be zero.")
        return (value - mean) / std_dev

    # Calculates the Z-score for a Bernoulli variable (0 or 1) based on the rate (probability of success)
    def z_score_bernoulli(self, flag: bool, rate: float) -> float:
        if rate <= 0 or rate >= 1:
            raise ValueError("Rate must be between 0 and 1 (exclusive).")
        
        if flag:
            return (1 - rate) / math.sqrt(rate * (1 - rate))
        else:
            return -rate / math.sqrt(rate * (1 - rate))
        
    # Applies a sigmoid transformation to the Z-score to convert it into a value between 0 and 1    
    def sigmoid(self, z_score: float) -> float:
        return 1 / (1 + math.exp(-self.k * (z_score - self.mu)))

    # Combines the sigmoid-transformed Z-score with a weight to produce a composite score
    def weighted_composite_score(self, sig_off_hours: float, sig_hour: float, sig_freq: float, sig_weekend: float) -> float:
        return sig_off_hours * 0.35 + sig_hour * 0.25 + sig_freq * 0.2 + sig_weekend * 0.2



