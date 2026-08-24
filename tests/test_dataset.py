import numpy as np

from models.dataset import FeatureScaler


def test_fit_floors_near_zero_std():
    X = np.array([[1.0, 5.0], [1.0, 6.0], [1.0, 7.0]])  # first column is constant
    scaler = FeatureScaler().fit(X)
    assert scaler.std[0] == 1.0  # floored, not zero (would divide by zero otherwise)


def test_transform_clips_out_of_distribution_values():
    X = np.tile(np.array([[10.0]]), (50, 1))  # constant training feature -> std floored to 1.0
    scaler = FeatureScaler(clip_std=6.0).fit(X)

    ordinary = scaler.transform(np.array([[11.0]]))  # 1 std away, well within the clip range
    extreme = scaler.transform(np.array([[1000.0]]))  # far out-of-distribution

    assert abs(ordinary[0, 0]) < 6.0
    assert extreme[0, 0] == 6.0  # clipped, not left to blow up to ~990


def test_transform_clips_negative_extreme_too():
    X = np.tile(np.array([[10.0]]), (50, 1))
    scaler = FeatureScaler(clip_std=6.0).fit(X)
    extreme = scaler.transform(np.array([[-1000.0]]))
    assert extreme[0, 0] == -6.0


def test_save_load_round_trip_preserves_clip_std(tmp_path):
    scaler = FeatureScaler(mean=np.array([1.0, 2.0]), std=np.array([3.0, 4.0]), clip_std=3.0)
    path = tmp_path / "scaler.npz"
    scaler.save(path)

    loaded = FeatureScaler.load(path)

    np.testing.assert_array_equal(loaded.mean, scaler.mean)
    np.testing.assert_array_equal(loaded.std, scaler.std)
    assert loaded.clip_std == 3.0


def test_inverse_transform_undoes_transform_within_clip_range():
    X = np.array([[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]])
    scaler = FeatureScaler().fit(X)
    row = np.array([2.0, 3.0])  # inside the clip range for this small a spread
    np.testing.assert_allclose(scaler.inverse_transform(scaler.transform(row)), row, atol=1e-5)
