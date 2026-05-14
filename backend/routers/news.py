from fastapi import APIRouter
from services import news

router = APIRouter()


@router.get("/news")
async def get_news():
    items = await news.fetch_news()
    return {"items": items}
