from .existing_model import RiskScoreModel
from .weighted_circular_distance import weighted_circular_distance, hybrid_scoring

# To represent the hybrid risk score model that combines the existing risk score model with the weighted circular distance model
class HybridScoreModel(RiskScoreModel):
    def __init__(self, k: float = 1.0, mu: float = 2.0):
        """
        Parameters:
            k (float): The steepness of the sigmoid curve. Default is 1.0.
            mu (float): The midpoint of the sigmoid curve. Default is 2.0.
        """
        super().__init__(k, mu)

    # Computes the weighted circular distance for a given input
    def compute_weighted_circular_distance(self, x: int, bins: list[int], weekend_flag: bool) -> float:
        return weighted_circular_distance(x, bins, weekend_flag)
    
    # Computes the hybrid score for a given input
    def compute_hybrid_score(self, x: int, bins: list[int], weekend_flag: bool) -> float:
        return hybrid_scoring(x, bins, weekend_flag)