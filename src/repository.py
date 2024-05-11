from database import new_session, ScansTable
from schemas import NewScan, Scan
from sqlalchemy import select, update, delete
from datetime import datetime


class ScansRepository:
    @classmethod
    async def create_new_scan(cls, scan_data: NewScan) -> int:
        async with new_session() as session:
            scan_dict = scan_data.model_dump()
            scan = ScansTable(**scan_dict)
            session.add(scan)
            await session.flush()
            await session.commit()
            return scan.id

    @classmethod
    async def delete_scan_by_id(cls, scan_id: int):
        async with new_session() as session:
            query = delete(ScansTable).where(ScansTable.id == scan_id)
            await session.execute(query)
            await session.commit()

    @classmethod
    async def get_all_scans(cls) -> list[Scan]:
        async with new_session() as session:
            query = select(ScansTable)
            result = await session.execute(query)
            scan_modules = result.scalars().all()
            return scan_modules

    @classmethod
    async def edit_result_of_scan_by_id(cls, scan: Scan, result_data) -> list[Scan]:
        async with new_session() as session:
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d")
            date = "finished->" + formatted_datetime
            scan_id = scan.get("id")
            query = update(ScansTable).values(result=result_data, status=date).filter_by(id=scan_id)
            await session.execute(query)
            await session.commit()

