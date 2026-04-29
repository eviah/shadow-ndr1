# -*- coding: utf-8 -*-
"""
Breach Horizon API — predictive risk scoring per asset.

GET  /api/breach-horizon              → top-N at-risk assets (current tenant)
GET  /api/breach-horizon/{asset_id}   → forecast for one asset
POST /api/breach-horizon/retrain      → force model retrain (admin)
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from loguru import logger
from pydantic import BaseModel

from ..db import db
from ..ml.breach_horizon import HorizonForecast, get_horizon_model

router = APIRouter(prefix="/api/breach-horizon", tags=["breach-horizon"])


class HorizonOut(BaseModel):
    asset_id: int
    breach_probability: float
    horizon_hours: float
    band: str
    drivers: List[str]
    model_version: str

    @classmethod
    def from_forecast(cls, f: HorizonForecast) -> "HorizonOut":
        return cls(
            asset_id=f.asset_id,
            breach_probability=f.breach_probability,
            horizon_hours=f.horizon_hours,
            band=f.band,
            drivers=f.drivers,
            model_version=f.model_version,
        )


@router.get("/{asset_id}", response_model=HorizonOut)
async def forecast_one(asset_id: int):
    model = get_horizon_model()
    f = await model.predict(db, asset_id)
    return HorizonOut.from_forecast(f)


@router.get("", response_model=List[HorizonOut])
async def forecast_top(
    limit: int = Query(20, ge=1, le=100),
    min_band: str = Query("amber", pattern="^(green|amber|orange|red)$"),
):
    """Return assets at or above the requested risk band, worst first."""
    BAND_ORDER = {"green": 0, "amber": 1, "orange": 2, "red": 3}
    threshold = BAND_ORDER[min_band]

    rows = await db.fetch(
        "SELECT id FROM assets ORDER BY id LIMIT $1",
        max(limit * 4, 50),
    )
    model = get_horizon_model()
    await model.maybe_train(db)

    out: List[HorizonOut] = []
    for r in rows:
        f = await model.predict(db, r["id"])
        if BAND_ORDER[f.band] >= threshold:
            out.append(HorizonOut.from_forecast(f))

    out.sort(key=lambda x: x.breach_probability, reverse=True)
    return out[:limit]


@router.post("/retrain")
async def retrain():
    model = get_horizon_model()
    await model.maybe_train(db, min_rows=50)
    return {
        "trained_at": model.trained_at,
        "train_rows": model.train_rows,
        "model_version": (
            f"gbc-{int(model.trained_at)}" if model.trained_at else "heuristic-v1"
        ),
    }
