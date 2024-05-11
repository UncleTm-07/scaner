from fastapi import APIRouter
from schemas import NewScan, Scan
from repository import ScansRepository

router = APIRouter(
    prefix="/scans",
    tags=["Scans"]
)


@router.get("")
async def get_all_scans() -> list[Scan]:
    scans = await ScansRepository.get_all_scans()
    return scans


@router.post("")
async def create_scan(scan: NewScan):
    scan_id = await ScansRepository.create_new_scan(scan)
    return {
        "scan_id": scan_id
    }


@router.delete("/{scan_id}")
async def create_scan(scan_id: int):
    await ScansRepository.delete_scan_by_id(scan_id)
    return {
        "status": True
    }

