import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from models.tree_export import export_hgb, load_flat, predict_proba_flat


def _data(seed=0, n=3000, f=6):
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, f))
    X[:, 2] = np.round(X[:, 2])                      # ties / few distinct values
    y = ((X[:, 0] + 0.5 * X[:, 1] * X[:, 3] + 0.3 * rng.normal(size=n)) > 0.3).astype(int)
    return X, y


def test_flat_predictor_matches_sklearn_exactly_and_roundtrips(tmp_path):
    X, y = _data()
    clf = HistGradientBoostingClassifier(max_iter=60, early_stopping=False, random_state=0).fit(X, y)
    arrays = export_hgb(clf, [f"f{i}" for i in range(X.shape[1])], tmp_path / "m.npz", threshold=0.4)
    Xt, _ = _data(seed=1, n=1000)
    ref = clf.predict_proba(Xt)[:, 1]
    assert np.allclose(predict_proba_flat(arrays, Xt), ref, atol=1e-9)
    loaded = load_flat(tmp_path / "m.npz")                       # allow_pickle=False round trip
    assert np.allclose(predict_proba_flat(loaded, Xt), ref, atol=1e-9)
    Xn = Xt.copy()
    Xn[::7, 1] = np.nan                                           # missing values follow the stored direction
    assert np.allclose(predict_proba_flat(loaded, Xn), clf.predict_proba(Xn)[:, 1], atol=1e-9)
    assert all(a.dtype != object for a in loaded.values())
