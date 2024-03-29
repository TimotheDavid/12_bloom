# For python 3.9 syntax compliance
from typing import Union, List, Any

from bloom.config import settings
from bloom.domain.port import Port
from bloom.infra.database import sql_model
from bloom.logger import logger

import pandas as pd
import geopandas as gpd
from dependency_injector.providers import Callable
from geoalchemy2.shape import from_shape, to_shape
from shapely.geometry import Polygon
from sqlalchemy.orm import Session
from sqlalchemy import select, update, or_
from shapely import Point
from sqlalchemy import func
from geoalchemy2.shape import from_shape
from datetime import datetime


class PortRepository:
    def __init__(self, session_factory: Callable) -> None:
        self.session_factory = session_factory

    def get_port_by_id(self, session: Session, port_id: int) -> Union[Port, None]:
        entity = session.get(sql_model.Port, port_id).scalar()
        if entity is not None:
            return PortRepository.map_to_domain(entity)
        else:
            return None

    def get_all_ports(self, session: Session) -> List[Port]:
        q = session.query(sql_model.Port)
        if not q:
            return []
        return [PortRepository.map_to_domain(entity) for entity in q]

    def get_empty_geometry_buffer_ports(self, session: Session) -> list[Port]:
        stmt = select(sql_model.Port).where(sql_model.Port.geometry_buffer.is_(None))
        q = session.execute(stmt).scalars()
        if not q:
            return []
        return [PortRepository.map_to_domain(entity) for entity in q]

    def get_ports_updated_created_after(self, session: Session, created_updated_after: datetime) -> list[Port]:
        stmt = select(sql_model.Port).where(or_(sql_model.Port.created_at >= created_updated_after,
                                                sql_model.Port.updated_at >= created_updated_after))
        q = session.execute(stmt).scalars()
        if not q:
            return []
        return [PortRepository.map_to_domain(entity) for entity in q]

    def update_geometry_buffer(self, session: Session, port_id: int, buffer: Polygon) -> None:
        session.execute(update(sql_model.Port), [{"id": port_id, "geometry_buffer": from_shape(buffer)}])

    def batch_update_geometry_buffer(self, session: Session, id_buffers: list[dict[str, Any]]) -> None:
        items = [{"id": item["id"], "geometry_buffer": from_shape(item["geometry_buffer"])} for item in id_buffers]
        session.execute(update(sql_model.Port), items)

    def create_port(self, session: Session, port: Port) -> Port:
        orm_port = PortRepository.map_to_sql(port)
        session.add(orm_port)
        return PortRepository.map_to_domain(orm_port)

    def batch_create_port(self, session: Session, ports: list[Port]) -> list[Port]:
        orm_list = [PortRepository.map_to_sql(port) for port in ports]
        session.add_all(orm_list)
        return [PortRepository.map_to_domain(orm) for orm in orm_list]

    def find_port_by_position_in_port_buffer(self, session: Session, position: Point) -> Union[Port | None]:
        stmt = select(sql_model.Port).where(
            func.ST_contains(sql_model.Port.geometry_buffer, from_shape(position, srid=settings.srid)) == True)
        port = session.execute(stmt).scalar()
        if not port:
            return None
        else:
            return PortRepository.map_to_domain(port)
        
    def find_positions_in_port_buffer(
            self, session: Session, vessel_positions: List[tuple]
        ) -> List[tuple]:
        """Assigns vessel positions to their port if any. If a vessel is not in a port,
        assign np.nan as port_id

        :param List[tuple] vessel_positions: fields "vessel_id", "longitude", "latitude", 

        :return List[tuple] vessel_positions: fields "vessel_id", "longitude", "latitude", "port_name", "port_id"
            if a vessel is not in a port, "port_id" is np.nan
        """

        # Convert vessel positions into a GeoDataFrame
        df_vessel_positions = pd.DataFrame(
            vessel_positions, columns=["vessel_id", "lon", "lat"]
        )
        gdf_vessel_positions = gpd.GeoDataFrame(
            df_vessel_positions,
            geometry=gpd.points_from_xy(
                df_vessel_positions["lon"], df_vessel_positions["lat"]
            ),
            crs=settings.srid,
        )

        # Get all ports from DataBase
        ports = self.get_all_ports(session)
        df_ports = pd.DataFrame(
            [[p.id, p.name, p.geometry_buffer] for p in ports],
            columns=["port_id", "port_name", "geometry"],
        )
        gdf_ports = gpd.GeoDataFrame(df_ports, geometry="geometry", crs=settings.srid)

        # Spatial join to match vessel positions to ports polygons
        gdf_vessel_positions = gdf_vessel_positions.sjoin(gdf_ports, how="left")

        # Format response as list of tuples with port_id as last element
        response = list(
            zip(
                gdf_vessel_positions["vessel_id"],
                gdf_vessel_positions["lon"],
                gdf_vessel_positions["lat"],
                gdf_vessel_positions["port_id"],
                gdf_vessel_positions["port_name"],
            )
        )

        return response

    @staticmethod
    def map_to_domain(orm_port: sql_model.Port) -> Port:
        return Port(
            id=orm_port.id,
            name=orm_port.name,
            locode=orm_port.locode,
            url=orm_port.url,
            country_iso3=orm_port.country_iso3,
            latitude=orm_port.latitude,
            longitude=orm_port.longitude,
            geometry_point=to_shape(orm_port.geometry_point),
            geometry_buffer=to_shape(orm_port.geometry_buffer)
            if orm_port.geometry_buffer is not None
            else None,
            has_excursion=orm_port.has_excursion,
            created_at=orm_port.created_at,
            updated_at=orm_port.updated_at,
        )

    @staticmethod
    def map_to_sql(port: Port) -> sql_model.Port:
        return sql_model.Port(
            name=port.name,
            locode=port.locode,
            url=port.url,
            country_iso3=port.country_iso3,
            latitude=port.latitude,
            longitude=port.longitude,
            geometry_point=from_shape(port.geometry_point),
            geometry_buffer=from_shape(port.geometry_buffer)
            if port.geometry_buffer is not None
            else None,
            has_excursion=port.has_excursion,
            created_at=port.created_at,
            updated_at=port.updated_at,
        )
