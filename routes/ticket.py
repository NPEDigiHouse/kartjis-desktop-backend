import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import HTTPException, Request, Response
from sqlalchemy.ext.asyncio import create_async_engine

import jwt
import hashlib
import pytz
import random
import uuid
from fastapi import APIRouter, Query, Response, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from config.db import online_engine, online_engine2
import uvicorn
import bcrypt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security, Depends
import httpx

security = HTTPBearer()
SECRET_KEY = "a_very_secret_key_1234567890!@#$%^&*()"
ALGORITHM = "HS256"


ticket = APIRouter()


@ticket.get("/")
async def root():
    return {"message": "CORS sudah aktif!"}

# LOGIN


class LoginData(BaseModel):
    username: str
    password: str


# Fungsi untuk membuat token JWT


def create_token(user_data: dict):
    expiration = datetime.utcnow() + timedelta(days=7)
    payload = {**user_data, "exp": expiration}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# Fungsi untuk mengambil user dari token


async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Endpoint login yang menghasilkan token


@ticket.post('/api/users/login')
async def login(login_data: LoginData, response: Response):
    try:
        if (login_data.username == 'kakimenapak'):
            return await loginOld(login_data, response)

        async with online_engine.begin() as conn:
            fetch_query = f"""
            select u.id, u.username, u.roles='EVENT_ORGANIZER' as "isAdmin", eo.event_id "eventId", u."name", u.email, u.password  from users u
            join event_organizers eo on eo.username  = u.username or eo.username = u.supervisor_id 
            WHERE u.username = :username
            """
            result = await conn.execute(text(fetch_query), {"username": login_data.username})
            user = result.fetchone()

            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            hashed_password = user.password
            if hashed_password.startswith("{bcrypt}"):
                hashed_password = hashed_password.replace("{bcrypt}", "", 1)

            if not bcrypt.checkpw(login_data.password.encode('utf-8'), hashed_password.encode('utf-8')):
                raise HTTPException(
                    status_code=401, detail="Invalid credentials")

            # Buat token JWT yang menyimpan eventId
            token = create_token({
                "username": user.username,
                "eventId": user.eventId
            })

            return {
                "status": "SUCCESS",
                "message": "Login successful",
                "data": {
                    "userId": user.id,
                    "username": user.username,
                    "isAdmin": user.isAdmin == 1,
                    "eventId": user.eventId,
                    "name": user.name,
                    "email": user.email,
                    "token": token
                }
            }
    except HTTPException as e:
        response.status_code = e.status_code
        return {"success": False, "error": e.detail}
    except Exception as e:
        print(e)
        response.status_code = 500
        return {"success": False, "error": "An internal server error occurred"}


# GEt ORDERS
@ticket.get('/api/events/orders')
async def read_orders(
    response: Response,
    search: str = Query(default=None, description="Search by name or email"),
    user: dict = Depends(get_current_user)  # Ambil user dari token
):

    if (user["username"] == "kakimenapak"):
        return await read_orders_old(response=response, search=search, user=user)

    try:
        event_id = user["eventId"]  # Ambil eventId dari token
        async with online_engine.begin() as conn:
            base_query = f"""
            SELECT 
                o.id AS "id",
                t.id AS "orderId",
                tv.id AS "tvId",
                o.order_status_id,
                tc.name AS "ticketName",
                tc.price AS "ticketPrice",
                t2.created_at AS "orderCreatedAt",
                u.address, 
                tv.hash AS "hash",
                u2.name AS "verifiedByName",
                CASE
                    WHEN tv.scanned_at IS NULL THEN FALSE
                    WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE
                    ELSE TRUE
                END AS "isVerified",
                tv.scanned_at AS "verifiedAt",
                tv.un_scanned_at AS "unverifiedAt",
                tv.scanned_by AS "verifiedBy",
                tv.un_scanned_by AS "unverifiedBy",
                -- Subquery untuk mendapatkan ticketNum
                ROW_NUMBER() OVER (PARTITION BY t.order_id ORDER BY t.id) AS "ticketNum",
                -- Subquery untuk mendapatkan ticketCount
                COUNT(*) OVER (PARTITION BY t.order_id) AS "ticketCount",
                t.customer_email AS "email",
                t.customer_name AS "name",
                t.customer_gender AS "gender",
                t.customer_phone_number AS "phoneNumber",
                tc.id AS "ticketId"
            FROM orders o
            JOIN tickets t ON t.order_id = o.id
            JOIN transactions t2 ON t2.order_id = o.id  
            LEFT JOIN ticket_verification tv ON tv.ticket_code = t.code 
            LEFT JOIN users u2 ON u2.id = tv.scanned_by
            LEFT JOIN ticket_categories tc ON tc.id = t.ticket_category_id
            LEFT JOIN users u ON u.email = o.customer_id 
            LEFT JOIN ticket_custom_fields tcf ON tcf.ticket_id = t.id
            WHERE t.event_id = :event_id
            AND o.order_status_id = 1
            """

            params = {'event_id': event_id}
            if search:
                base_query += " AND (LOWER(t.customer_name) LIKE LOWER(:search) OR LOWER(t.customer_email) LIKE LOWER(:search))"
                params['search'] = f"%{search}%"

            base_query += " ORDER BY t.customer_name"

            result_proxy = await conn.execute(text(base_query), params)
            data = result_proxy.fetchall()

            formatted_data = []
            for row in data:
                row_dict = dict(row)
                formatted_row = {
                    "address": "-",
                    "name": row_dict["name"],
                    "birthDate": "",
                    "email": row_dict["email"],
                    "gender": row_dict["gender"],
                    "id": row_dict["id"],
                    "commiteeName": "",
                    "orderId": row_dict["orderId"],
                    "phoneNumber": row_dict["phoneNumber"],
                    "socialMedia": '',
                    "ticketId": row_dict["ticketId"],
                    "verifiedAt": row_dict["verifiedAt"],
                    "ticket": {
                        "id": row_dict["ticketId"],
                        "name": row_dict["ticketName"],
                        "eventId": event_id,
                        "price": row_dict["ticketPrice"]
                    },
                    "eventId": event_id,
                    "orderCreatedAt": row_dict["orderCreatedAt"],
                    "isScanned": bool(row_dict["isVerified"]),
                    "hash": row_dict["hash"],
                    "ticketCount": row_dict.get("ticketCount", 0),
                    "ticketNum": row_dict.get("ticketNum", 0),
                    "verifiedBy": {
                        "id": row_dict.get("verifiedById"),
                        "name": row_dict.get("verifiedByName"),
                    },
                    "isHide": False
                }

                formatted_data.append(formatted_row)

        return {
            "status": "SUCCESS",
            "data": formatted_data
        }

    except Exception as e:
        print(e)
        response.status_code = 500
        return {"success": False, "error": str(e)}


class EmailData(BaseModel):
    email: str


@ticket.put('/api/tickets/resend/{order_id}')
async def resend_ticket(order_id: str, response: Response, email_data: EmailData):
    try:
        async with online_engine.begin() as conn:
            query = """
            SELECT 
                t.customer_name AS customerName,
                tc.name AS ticketName,
                o.id AS orderId,
                t2.created_at AS transactionCreatedAt,
                t2.payment_type AS transactionSource,
                t.customer_email AS customeremail,
                e.name AS eventName
            FROM tickets t
            JOIN ticket_categories tc ON tc.id = t.ticket_category_id
            JOIN events e ON e.id = t.event_id
            JOIN orders o ON o.id = t.order_id
            JOIN transactions t2 ON t2.order_id = o.id
            WHERE o.id = :order_id AND t.customer_email = :email;
            """

            result = await conn.execute(text(query), {"order_id": order_id, "email": email_data.email})
            rows = result.mappings().fetchall()

            if not rows:
                response.status_code = 404
                return {"status": "NOT_FOUND", "message": "Ticket not found"}

        # Send to external API
            payload = {
                "customerName": rows[0]["customername"],
                "ticketName": rows[0]["ticketname"],
                "orderNumber": rows[0]["orderid"],
                "orderDate": str(rows[0]["transactioncreatedat"]),
                "paymentMethod": rows[0]["transactionsource"],
                "redirectLink": f"https://kartjis.id/my-kartjis/{rows[0]['orderid']}",
                "email": email_data.email,
                "eventName": rows[0]["eventname"]
            }

        async with httpx.AsyncClient() as client:
            api_response = await client.post("http://103.127.134.84:9877", json=payload)
            api_result = api_response.json()

        return {"status": "SUCCESS", "data": api_result}

    except Exception as e:
        print(e)
        response.status_code = 500
        return {"status": "ERROR", "error": str(e)}


class TicketData(BaseModel):
    email: str
    name: str


@ticket.put('/api/tickets2/{ticket_id}')
async def update_ticket(ticket_id: str, ticket_data: TicketData, response: Response):
    try:
        async with online_engine.begin() as conn:
            update_query = """
            UPDATE tickets
            SET customer_email = :email,
                customer_name = :name
            WHERE id = :ticket_id
            """
            params = {
                "email": ticket_data.email,
                "name": ticket_data.name,
                "ticket_id": ticket_id,
            }

            result = await conn.execute(text(update_query), params)

            if result.rowcount == 0:
                response.status_code = 404
                return {"success": False, "message": "Ticket not found"}

        return {"status": "SUCCESS", "message": "Ticket updated successfully"}
    except Exception as e:
        print(e)
        response.status_code = 500
        return {"success": False, "error": str(e)}

# GET EVENTs

@ticket.get("/api/events2")
async def get_event_details2(response: Response, user: dict = Depends(get_current_user)):
    event_id = user["eventId"]
    try:
        async with online_engine.connect() as conn:
            event_query = f"""
            select e.id as "eventId", e."name" as "eventName", tc.id as "ticketId", tc."name" as "ticketName", tc.price as "ticketPrice", tc.staff_only as "isOffline", vtcs.available_stock as "stock", tc.ticket_category_status_id as "ticket_category_status_id", tc.sales_end_time as "sales_end_time" from events e
            left join ticket_categories tc on tc.event_id = e.id
            join view_ticket_category_stock vtcs on vtcs.ticket_category_id  = tc.id
            WHERE e.id = :event_id
            """

            result = await conn.execute(text(event_query), {"event_id": event_id})
            rows = result.fetchall()

            if not rows:
                response.status_code = 404
                return {"status": "NOT_FOUND", "message": "Event not found"}

            def is_available(row):
                status_ok = row['ticket_category_status_id'] == 1
                sales_end = row['sales_end_time']
                # Pastikan sales_end adalah timezone-aware (UTC)
                if sales_end.tzinfo is None:
                    sales_end = sales_end.replace(tzinfo=timezone.utc)
                return status_ok and (sales_end + timedelta(hours=8)) > datetime.now(timezone.utc)

            # Extract event details
            event_data = {
                "id": rows[0]["eventId"],
                "banner": '',
                "name": rows[0]["eventName"],
                "tickets": [
                    {
                        "id": row["ticketId"],
                        "name": row["ticketName"],
                        "eventId": event_id,
                        "price": row["ticketPrice"],
                        "stock": row['stock'],
                        "isOffline": row['isOffline'],
                        "isAvailable": is_available(row)
                    } for row in rows if row["ticketId"]
                ]
            }

        return {
            "status": "SUCCESS",
            "data": event_data
        }

    except Exception as e:
        print(e)
        response.status_code = 500
        return {
            "status": "ERROR",
            "message": str(e)
        }

@ticket.get('/api/events/ticket-type-summary')
async def ticket_type_summary(
    response: Response,
    user: dict = Depends(get_current_user)
):

    if (user["username"] == "kakimenapak"):
        return await ticket_type_summary_old(response=response, user=user)

    try:
        event_id = user["eventId"]
        async with online_engine.begin() as conn:

            summary_query = """
                SELECT
                    tc.name AS ticket_type_name,
                    COALESCE(COUNT(od.id), 0) AS total_sold,
                    COALESCE(SUM(CASE WHEN od.customer_gender = 'MALE' THEN 1 ELSE 0 END), 0) AS male_count,
                    COALESCE(SUM(CASE WHEN od.customer_gender = 'FEMALE' THEN 1 ELSE 0 END), 0) AS female_count,
                    tc.price AS ticket_price,
                    tc.stock AS stock,
                    e.admin_fee AS admin_fee,
                    COALESCE(tc.price * COUNT(od.id), 0) AS total_price,
                    COALESCE((tc.price * COUNT(od.id)) + (COUNT(od.id) * e.admin_fee), 0) AS revenue_after_admin_fee,
                    COALESCE(SUM(CASE WHEN tv.scanned_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS verified_count,
                    COALESCE(SUM(CASE WHEN tv.scanned_at IS NULL THEN 1 ELSE 0 END), 0) AS unverified_count
                FROM ticket_categories AS tc
                LEFT JOIN tickets AS od ON od.ticket_category_id = tc.id
                LEFT JOIN orders AS o ON od.order_id = o.id
                LEFT JOIN ticket_verification tv ON tv.ticket_code = od.code 
                LEFT JOIN events e ON e.id = od.event_id 
                WHERE od.event_id = :event_id AND order_status_id = 1 and o.entry_by = 'anonymous'
                GROUP BY tc.id, tc.name, tc.price, tc.stock, e.admin_fee
                ORDER BY tc.name
                """

            params = {'event_id': event_id}
            result_proxy = await conn.execute(text(summary_query), params)
            data = result_proxy.fetchall()

            summary_query_offline = """
                SELECT
                    tc.name AS ticket_type_name,
                    COALESCE(COUNT(od.id), 0) AS total_sold,
                    COALESCE(SUM(CASE WHEN od.customer_gender = 'MALE' THEN 1 ELSE 0 END), 0) AS male_count,
                    COALESCE(SUM(CASE WHEN od.customer_gender = 'FEMALE' THEN 1 ELSE 0 END), 0) AS female_count,
                    tc.price AS ticket_price,
                    tc.stock AS stock,
                    e.admin_fee AS admin_fee,
                    COALESCE(tc.price * COUNT(od.id), 0) AS total_price,
                    COALESCE((tc.price * COUNT(od.id)) + (COUNT(od.id) * e.admin_fee), 0) AS revenue_after_admin_fee,
                    COALESCE(SUM(CASE WHEN tv.scanned_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS verified_count,
                    COALESCE(SUM(CASE WHEN tv.scanned_at IS NULL THEN 1 ELSE 0 END), 0) AS unverified_count
                FROM ticket_categories AS tc
                LEFT JOIN tickets AS od ON od.ticket_category_id = tc.id
                LEFT JOIN orders AS o ON od.order_id = o.id
                LEFT JOIN ticket_verification tv ON tv.ticket_code = od.code 
                LEFT JOIN events e ON e.id = od.event_id 
                WHERE od.event_id = :event_id AND order_status_id = 1 and o.entry_by != 'anonymous'
                GROUP BY tc.id, tc.name, tc.price, tc.stock, e.admin_fee
                ORDER BY tc.name
                """

            params_offline = {'event_id': event_id}
            result_proxy_offline = await conn.execute(text(summary_query_offline), params_offline)
            data_offline = result_proxy_offline.fetchall()

            ticket_counts_online = [
                {
                    "ticketTypeName": row["ticket_type_name"] or "",
                    "totalSold": row["total_sold"] or 0,
                    "maleCount": row["male_count"] or 0,
                    "femaleCount": row["female_count"] or 0,
                    "ticketPrice": row["ticket_price"] or 0,
                    "totalPrice": row["total_price"] or 0,
                    "adminFee": row["admin_fee"] or 0,
                    "stock": row["stock"] or 0,
                    "revenueAfterAdminFee": row["revenue_after_admin_fee"] or 0,
                    "verifiedCount": row["verified_count"] or 0,
                    "unverifiedCount": row["unverified_count"] or 0,
                }
                for row in data
            ]

            ticket_counts_offline = [
                {
                    "ticketTypeName": row["ticket_type_name"] + ' (OFFLINE)' or "",
                    "totalSold": row["total_sold"] or 0,
                    "maleCount": row["male_count"] or 0,
                    "femaleCount": row["female_count"] or 0,
                    "ticketPrice": row["ticket_price"] or 0,
                    "totalPrice": row["total_price"] or 0,
                    "adminFee": row["admin_fee"] or 0,
                    "stock": row["stock"] or 0,
                    "revenueAfterAdminFee": row["revenue_after_admin_fee"] or 0,
                    "verifiedCount": row["verified_count"] or 0,
                    "unverifiedCount": row["unverified_count"] or 0,
                }
                for row in data_offline
            ]

            ticket_counts = ticket_counts_online + ticket_counts_offline

            # Gunakan ticket_counts agar semua value sudah pasti ada dan tidak None
            total_tickets = sum(row["totalSold"] for row in ticket_counts)
            total_verified = sum(row["verifiedCount"] for row in ticket_counts)
            total_unverified = sum(row["unverifiedCount"]
                                   for row in ticket_counts)
            online_revenue = sum(row["totalPrice"]
                                 for row in ticket_counts_online)
            offline_revenue = sum(row["totalPrice"]
                                  for row in ticket_counts_offline)

            ticket_summary = {
                "total": total_tickets,
                "verifiedCount": total_verified,
                "unverifiedCount": total_unverified,
                "onlineRevenue": online_revenue,
                "offlineRevenue": offline_revenue,
            }

            return {
                "status": "SUCCESS",
                "data": {
                    "ticketSummary": ticket_summary,
                    "ticketCounts": ticket_counts
                }
            }

    except Exception as e:
        print("❌ Error:", e)
        response.status_code = 500
        return {
            "status": "ERROR",
            "error": str(e)
        }


# GET EVENTs
@ticket.get("/api/events")
async def get_event_details2(response: Response, user: dict = Depends(get_current_user)):
    if (user["username"] == "kakimenapak"):
        print("old")
        return await get_event_details_old(response=response, user=user)
    event_id = user["eventId"]
    try:
        async with online_engine.connect() as conn:
            event_query = f"""
            select e.id as "eventId", e."name" as "eventName", tc.id as "ticketId", tc."name" as "ticketName", tc.price as "ticketPrice"
            from events e
            left join ticket_categories tc on tc.event_id = e.id
            WHERE e.id = :event_id
            """

            result = await conn.execute(text(event_query), {"event_id": event_id})
            rows = result.fetchall()

            if not rows:
                response.status_code = 404
                return {"status": "NOT_FOUND", "message": "Event not found"}

            # Extract event details
            event_data = {
                "id": rows[0]["eventId"],
                "banner": '',
                "name": rows[0]["eventName"],
                "tickets": [
                    {
                        "id": row["ticketId"],
                        "name": row["ticketName"],
                        "eventId": event_id,
                        "price": row["ticketPrice"]
                    } for row in rows if row["ticketId"]
                ]
            }

        return {
            "status": "SUCCESS",
            "data": event_data
        }

    except Exception as e:
        print(e)
        response.status_code = 500  # Internal Server Error
        return {
            "status": "ERROR",
            "message": str(e)}


@ticket.delete('/api/orders/{id}')
async def delete_order(id: str, response: Response):
    try:
        async with online_engine.begin() as conn:
            # Delete query
            delete_query = f"DELETE FROM orders WHERE id = :id"
            result = await conn.execute(text(delete_query), {'id': id})

            # Check if any row was deleted
            if result.rowcount == 0:
                raise HTTPException(status_code=404, detail="Order not found")

        return {"status": "SUCCESS", "data": f"Order with ID {id} deleted successfully"}

    except HTTPException as e:
        raise e
    except Exception as e:
        print(e)
        response.status_code = 500  # Internal Server Error
        return {"status": "ERROR", "error": str(e)}


# GET EO
@ticket.get('/api/event-organizers')
async def get_event_organizers(response: Response, user: dict = Depends(get_current_user)):
    if (user["username"] == "kakimenapak"):
        return await get_event_organizers_old(response=response, user=user)

    try:
        eventId = user["eventId"]
        async with online_engine.begin() as conn:
            # Query untuk mendapatkan semua event organizers berdasarkan eventId
            fetch_query = f"""
            SELECT
                eo.id as id,
                eo.username as username,
                eo.name as name,
                eo.email as email,
                eo.roles as roles,
                COUNT(tv.id) AS "totalVerification"
            FROM users eo
            left JOIN ticket_verification as tv
                ON tv.scanned_by = eo.id
            left join event_organizers eo2 on eo2.username  = eo.username or eo2.username = eo.supervisor_id
            WHERE eo2.event_id = :eventId
            GROUP BY eo.id, eo.username, eo.name, eo.email, eo.roles
            """

            result = await conn.execute(text(fetch_query), {"eventId": eventId})
            event_organizers = result.fetchall()

            if not event_organizers:
                raise HTTPException(
                    status_code=404, detail="No Event Organizers found for this event"
                )

            # Mengubah hasil query menjadi list of dictionaries
            organizers_list = [
                {
                    "id": organizer.id,
                    "username": organizer.username,
                    "name": organizer.name,
                    "email": organizer.email,  # Properti phone ditambahkan
                    "isAdmin": organizer.roles == 'EVENT_ORGANIZER',
                    "totalVerification": organizer.totalVerification,
                }
                for organizer in event_organizers
            ]

            # Mengembalikan response sukses
            return {
                "status": "SUCCESS",
                "message": f"{len(organizers_list)} Event Organizer(s) fetched successfully",
                "data": organizers_list,
            }

    except HTTPException as e:
        response.status_code = e.status_code
        return {"success": False, "error": e.detail}
    except Exception as e:
        response.status_code = 500
        return {"success": False, "error": "An internal server error occurred"}


# ADD TICKET
class TicketBase(BaseModel):
    name: str
    price: float
    stock: int
    eventId: str


@ticket.post('/api/tickets')
async def create_ticket(ticket_data: TicketBase, response: Response, user: dict = Depends(get_current_user)):
    try:
        eventId = user["eventId"]
        async with online_engine.begin() as conn:
            insert_query = f"""
            INSERT INTO {db1}.tickets (name, price, stock, adminFee, eventId, id, updatedAt)
            VALUES (:name, :price, :stock, :adminFee, :eventId, :id, :updatedAt)
            """
            params = {
                "name": ticket_data.name,
                "price": ticket_data.price,
                "stock": ticket_data.stock,
                "adminFee": 10000,
                "eventId": eventId,
                "id": uuid.uuid4(),
                "updatedAt": datetime.now(),
            }

            await conn.execute(text(insert_query), params)

        return {"status": "SUCCESS", "message": "Ticket created successfully"}
    except Exception as e:
        print(e)
        response.status_code = 500  # Internal Server Error
        return {"success": False, "error": str(e)}

# UODATE TICKEt


@ticket.put('/api/tickets/{ticket_id}')
async def update_ticket(ticket_id: str, ticket_data: TicketBase, response: Response):
    try:
        async with online_engine.begin() as conn:
            update_query = f"""
            UPDATE {db1}.tickets
            SET name = :name, price = :price, stock = :stock
            WHERE id = :ticket_id
            """
            params = {
                "name": ticket_data.name,
                "price": ticket_data.price,
                "stock": ticket_data.stock,
                "ticket_id": ticket_id,
            }

            result = await conn.execute(text(update_query), params)

            if result.rowcount == 0:
                response.status_code = 404  # Not Found
                return {"success": False, "message": "Ticket not found"}

        return {"status": "SUCCESS", "message": "Ticket updated successfully"}
    except Exception as e:
        print(e)
        response.status_code = 500  # Internal Server Error
        return {"success": False, "error": str(e)}

# VERIFY


@ticket.put('/api/events/orders/{hash}')
async def update_verification(hash: str,  request: Request, response: Response, user: dict = Depends(get_current_user)):

    try:
        # Ambil data dari body request
        event_id = user["eventId"]
        body = await request.json()
        is_verify = body.get('isVerify')  # Mengambil nilai isVerify dari body
        verified_by = body.get('verifiedBy')  # ID user yang memverifikasi

        # Validasi body request
        if is_verify is None or not isinstance(is_verify, bool):
            response.status_code = 400  # Bad Request

            return {
                "success": False,
                "status": 'Failed',
                "code": '',
                "data": {
                    "code": "KARTJIS.44",
                    "detail": "'isVerify' harus berupa boolean."
                },
            }

        if not verified_by:
            response.status_code = 400  # Bad Request

            return {
                "success": False,
                "status": 'Failed',
                "code": '',
                "data": {
                    "code": "KARTJIS.44",
                    "detail": "'verifiedBy' tidak boleh kosong."
                },
            }

        # Set zona waktu lokal (misalnya waktu Makassar)
        local_tz = pytz.timezone("Asia/Makassar")
        aware_datetime = datetime.now(local_tz)

        # Convert to naive datetime, tapi dalam zona waktu Asia/Makassar
        current_datetime = aware_datetime.replace(tzinfo=None)

        async with online_engine.begin() as conn:
            # Query untuk memeriksa status tiket
            check_query = f"""
                SELECT 
                    o.id AS "id",
                    t.id AS "orderId",
                    tv.id AS "tvId",
                    o.order_status_id,
                    tc.name AS "ticketName",
                    tc.price AS "ticketPrice",
                    t2.created_at AS "orderCreatedAt",
                    u.address, 
                    tv.hash AS "hash",
                    u2.name as "verifiedByName",
                    tv.scanned_at IS NOT NULL AS "isVerified",
                    tv.scanned_at AS "verifiedAt",
                    tv.un_scanned_at AS "unverifiedAt",
                    tv.scanned_by AS "verifiedBy",
                    tv.un_scanned_by AS "unverifiedBy",
                    ROW_NUMBER() OVER (PARTITION BY t.order_id ORDER BY t.id) AS "ticketNum",
                    COALESCE(COUNT(*) OVER (PARTITION BY t.order_id), 0) AS "ticketCount",
                    t.customer_email AS "email",
                    t.customer_name AS "name",
                    t.customer_gender AS "gender",
                    t.customer_phone_number AS "phoneNumber",
                    tc.id AS "ticketId"
                FROM orders o
                JOIN tickets t ON t.order_id = o.id
                JOIN transactions t2 ON t2.order_id = o.id  
                LEFT JOIN ticket_verification tv ON tv.ticket_code = t.code 
                LEFT JOIN users u2 on u2.id = tv.scanned_by
                LEFT JOIN ticket_categories tc ON tc.id = t.ticket_category_id
                LEFT JOIN users u ON u.email = o.customer_id 
                LEFT JOIN ticket_custom_fields tcf ON tcf.ticket_id = t.id
                                WHERE (tv.hash = :hash or tv.ticket_code = :hash) and t.event_id = :event_id and order_status_id = 1
                ;
            """

            check_result = await conn.execute(text(check_query), {"hash": hash.lower(), "event_id": event_id})
            row_dict = check_result.fetchone()

            if not row_dict:
                response.status_code = 200  # Not Found
                return {
                    "success": False,
                    "status": 'Failed',
                    "code": '',
                    "data": {
                        "code": "KARTJIS.40",
                        "detail": "Kartjis tidak ditemukan."
                    },
                }

            # Ambil status verifikasi saat ini
            formatted_row = {
                "address": "",
                "name": row_dict["name"],
                "birthDate": "",
                "email": row_dict["email"],
                "gender": row_dict["gender"],
                "id": row_dict["id"],
                "commiteeName": "",
                "orderId": row_dict["orderId"],
                "phoneNumber": row_dict["phoneNumber"],
                "socialMedia": '',
                "ticketId": row_dict["ticketId"],
                "verifiedAt": row_dict["verifiedAt"],
                "ticket": {
                    "id": row_dict["ticketId"],
                    "name": row_dict["ticketName"],
                    "eventId": event_id,
                    "price": row_dict["ticketPrice"]
                },
                "eventId": event_id,
                "orderCreatedAt": row_dict["orderCreatedAt"],
                "isScanned": bool(row_dict["isVerified"]),
                "hash": row_dict["hash"],
                "ticketCount": row_dict["ticketCount"],
                "ticketNum": row_dict["ticketNum"],
                "verifiedBy": {
                    "id": row_dict["verifiedBy"],
                    "name": row_dict["verifiedByName"],
                },
                "isHide": False
            }

            if is_verify and bool(row_dict["isVerified"]):
                response.status_code = 200  # Bad Request
                return {
                    "success": False,
                    "status": 'Failed',
                    "code": '',
                    "data": {
                        "code": "KARTJIS.41",
                        "detail": "Kartjis sudah diverifikasi.",
                        "orderDetail": formatted_row,
                    }
                }

            # Update status verifikasi
            query_update = f"""
                UPDATE ticket_verification AS tv
                SET
                    scanned_at = :scanned_at,
                    scanned_by = :scanned_by,
                    un_scanned_at = :un_scanned_at,
                    un_scanned_by = :un_scanned_by
                FROM tickets t
                JOIN orders o ON o.id = t.order_id
                WHERE tv.ticket_code = t.code
                AND tv.hash = :hash or tv.ticket_code = :hash
                AND t.event_id = :event_id;
            """

            await conn.execute(text(query_update), {
                "scanned_at": current_datetime if is_verify else None,
                "un_scanned_at": None if is_verify else current_datetime,
                "scanned_by": verified_by if is_verify else None,
                "un_scanned_by": None if is_verify else verified_by,
                "hash": hash.lower(),
                "event_id": event_id,
            })

            query_user = f"""select u.name from users u where id = :id"""
            check_user = await conn.execute(text(query_user), {"id": verified_by})
            row_dict2 = check_user.fetchone()
            
            query_custom_fields = """
                SELECT name, value FROM ticket_custom_fields tcf
                JOIN tickets t ON t.id = tcf.ticket_id
                LEFT JOIN ticket_verification tv ON tv.ticket_code = t.code
                WHERE tv.hash = :hash;
            """

            custom_fields_result = await conn.execute(
                text(query_custom_fields),
                {"hash": hash.lower()}
            )

            formatted_row["citizenId"] = ''
            formatted_row["tshirtSize"] = ''
            # Response sukses

            formatted_row['isScanned'] = True if is_verify else False
            formatted_row['verifiedAt'] = current_datetime
            formatted_row['verifiedBy'] = {
                "id": verified_by,
                "name": row_dict2["name"],
            } if is_verify else {
                "id": verified_by,
                "name": row_dict2["name"],
            }

        return {
            "success": True,
            "status": 'SUCCEss',
            "code": '',
            "data": {
                "code": 'KARTJIS.21' if is_verify else "KARTJIS.20",
                "detail": "Berhasil memverifikasi Kartjis." if is_verify else "Berhasil membatalkan verifikasi Kartjis.",
                "orderDetail": formatted_row,
            },
        }

    except HTTPException as http_error:
        # Tangani HTTPException
        raise http_error
    except Exception as e:
        response.status_code = 500  # Internal Server Error
        return {
            "success": False,
            "status": 'Failed',
            "code": '',
                    "data": {
                        "code": "KARTJIS.50",
                        "detail": "Terjadi kesalahan internal server."
                    }
        },


# Add OTS
@ticket.post('/api/events/offline-transactions')
async def ots2(request: dict, response: Response,  user: dict = Depends(get_current_user)):
    tickets = request.get("data", [])
    event_id = user['eventId']
    ordal = request.get('ordal', False)

    async with online_engine.begin() as conn:
        try:
            if len(tickets) <= 0:
                return
            order_id = str(uuid.uuid4())
            current_time = datetime(
                year=2025, month=1, day=19) if ordal else datetime.now()
            customer_id = str(uuid.uuid4())
            ticket1 = tickets[0]

            await conn.execute(
                text(f"""INSERT INTO {db1}.customers (`id`, `name`, `email`, `birthDate`, `phoneNumber`, `gender`, `createdAt`, `updatedAt`) VALUES (:id, :name, :email, :birthDate, :phoneNumber, :gender, :createdAt, :updatedAt)"""),
                {
                    "id": customer_id,
                    "name": ticket1["customer_name"],
                    "email": ticket1["customer_email"],
                    "birthDate": ticket1["customer_birthdate"],
                    "phoneNumber": ticket1["customer_phone"],
                    "gender": ticket1["customer_gender"],
                    "createdAt": current_time,
                    "updatedAt": current_time,
                    "address": '',
                },
            )

            # Insert into `orders`
            await conn.execute(
                text(f"""
                    INSERT INTO {db1}.orders (`id`, `status`, `createdAt`, `updatedAt`, `customerId`, `eventId`)
                    VALUES (:id, 'SUCCESS', :createdAt, :updatedAt, :customerId, :eventId)
                """),
                {
                    "id": order_id,
                    "createdAt": current_time,
                    "updatedAt": current_time,
                    "eventId": event_id,
                    "customerId": customer_id
                },
            )

            # Insert into `customers`

            for ticket in tickets:
                ticket_id = ticket["ticket_id"],
                order_detail_id = str(uuid.uuid4())
                verification_id = str(uuid.uuid4())

                result = await conn.execute(
                    text(
                        f"SELECT id FROM {db1}.tickets WHERE `id` = :id and `eventId` = :eventId"),
                    {"id": ticket_id, "eventId": event_id},
                )
                existing_ticket = result.fetchone()

                if existing_ticket:
                    ticket_id = existing_ticket[0]
                else:
                    await conn.execute(
                        text(f"""
                            INSERT INTO {db1}.tickets (`id`, `name`, `price`, `eventId`, `stock`, `createdAt`, `updatedAt`, `adminFee`)
                            VALUES (:id, :name, :price, :eventId, :stock, :createdAt, :updatedAt, 0)
                        """),
                        {
                            "id": ticket_id,
                            "name": 'OTS',
                            "price": 0,
                            "eventId": event_id,
                            "stock": 100,
                            "createdAt": current_time,
                            "updatedAt": current_time,
                        },
                    )

                # Insert into `orderdetails`
                await conn.execute(
                    text(f"""
                        INSERT INTO {db1}.orderDetails (`id`, `ticketId`, `quantity`, `orderId`, `name`, `email`, `birthDate`, `phoneNumber`, `gender`, `address`, `socialMedia`, `location`, `commiteeName`)
                        VALUES (:id, :ticketId, 1, :orderId, :name, :email, :birthDate, :phoneNumber, :gender, :address, :socialMedia, :location, :commiteeName)
                    """),
                    {
                        "id": order_detail_id,
                        "ticketId": ticket_id,
                        "orderId": order_id,
                        "name": ticket["customer_name"],
                        "email": ticket["customer_email"],
                        "birthDate": ticket["customer_birthdate"],
                        "phoneNumber": ticket["customer_phone"],
                        "gender": ticket["customer_gender"],
                        "address": ticket["address"],
                        "socialMedia": ticket["social_media"],
                        "location": '666' if ordal else None,
                        "commiteeName": None,
                    },
                )

                # Generate MD5 hash for ticket verification
                random_number = random.randint(1000, 9999)
                combined_string = f"{ticket['customer_email']} {order_detail_id}{current_time}{random_number}"
                hash_value = hashlib.md5(combined_string.encode()).hexdigest()

                await conn.execute(
                    text(f"""
                        INSERT INTO {db1}.TicketVerification (`id`, `hash`, `isScanned`, `createdAt`, `updatedAt`, `orderDetailId`)
                        VALUES (:id, :hash, :isScanned, :createdAt, :updatedAt, :orderDetailId)
                    """),
                    {
                        "id": verification_id,
                        "hash": hash_value,
                        "isScanned": 0 if ordal else 1,
                        "createdAt": current_time,
                        "updatedAt": current_time,
                        "orderDetailId": order_detail_id,
                    },
                )

            return {
                "success": True,
                "data": "Tickets successfully created.",
            }

        except Exception as e:
            print(e)
            response.status_code = 500  # Internal Server Error
            return {
                "success": False,
                "error": str(e),
            }

# Bom verification


def assign_gender_rank(data_list):
    # Sort dulu berdasarkan orderCreatedAt, kalau sama urutkan berdasarkan email
    data_list.sort(key=lambda x: (x['orderCreatedAt'], x['email']))

    rank_counters = {}

    for item in data_list:
        gender = item['gender']
        if gender not in rank_counters:
            rank_counters[gender] = 0
        rank_counters[gender] += 1
        item['genderRank'] = f"{gender.upper()} {rank_counters[gender]}"
    return data_list


@ticket.get('/api/events/orders2')
async def read_orders2(
    response: Response,
    search: Optional[str] = Query(None, description="Search by name or email"),
    ticket_type: Optional[str] = Query(
        None, description="Filter by ticket type"),
    verified: Optional[bool] = Query(
        None, description="Filter by verification status (true/false)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(
        50, ge=1, le=3000, description="Number of results per page"),
    offline: Optional[bool] = Query(
        None, description="Filter by offline online"),
    user: dict = Depends(get_current_user),
):

    if (user["username"] == "kakimenapak"):
        return await read_orders2(
            response=response,
            search=search,
            ticket_type=ticket_type,
            verified=verified,
            page=page,
            page_size=page_size,
            user=user
        )
    try:
        event_id = user["eventId"]
        offset = (page - 1) * page_size

        async with online_engine.begin() as conn:
            base_query = text(f"""
SELECT 
    o.id AS "id",
    t.id AS "orderId",
    tv.id AS "tvId",
    o.order_status_id,
    tc.name AS "ticketName",
    tc.price AS "ticketPrice",
    t2.created_at AS "orderCreatedAt",
    u.address, 
    tv.hash AS "hash",
    o.entry_by AS "entryBy",
    u2.name AS "verifiedByName",
    CASE
        WHEN tv.scanned_at IS NULL THEN FALSE
        WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE
        ELSE TRUE
    END AS "isVerified",
    tv.scanned_at AS "verifiedAt",
    tv.un_scanned_at AS "unverifiedAt",
    tv.scanned_by AS "verifiedById",
    tv.un_scanned_by AS "unverifiedBy",
    MAX(CASE WHEN tcf.name = 'Tanggal Lahir' THEN tcf.value END) AS "birthDate",
    MAX(CASE WHEN tcf.name = 'Nomor Telpon Kontak Darurat' THEN tcf.value END) AS "emergencyCallNumber",
    MAX(CASE WHEN tcf.name = 'Nama Kontak Darurat' THEN tcf.value END) AS "emergencyCallName",
    MAX(CASE WHEN tcf.name = 'Alamat Lengkap' THEN tcf.value END) AS "fullAddress",
    MAX(CASE WHEN tcf.name = 'No. KTP' THEN tcf.value END) AS "citizenId",
    ROW_NUMBER() OVER (PARTITION BY t.order_id ORDER BY t.id) AS "ticketNum",
    COUNT(*) OVER (PARTITION BY t.order_id) AS "ticketCount",
    t.customer_email AS "email",
    t.customer_name AS "name",
    t.customer_gender AS "gender",
    t.customer_phone_number AS "phone",
    tc.id AS "ticketId"
FROM orders o
JOIN tickets t ON t.order_id = o.id
JOIN transactions t2 ON t2.order_id = o.id  
JOIN ticket_verification tv ON tv.ticket_code = t.code 
LEFT JOIN users u2 ON u2.id = tv.scanned_by
LEFT JOIN ticket_categories tc ON tc.id = t.ticket_category_id
LEFT JOIN users u ON u.email = o.customer_id 
LEFT JOIN ticket_custom_fields tcf ON tcf.ticket_id = t.id
WHERE t.event_id = :event_id
  AND o.order_status_id = 1

            """)

            count_query = text(f"""
            SELECT COUNT(*)
            FROM orders o
            right JOIN tickets t ON t.order_id = o.id
            JOIN ticket_categories tc ON tc.id = t.ticket_category_id
            JOIN ticket_verification tv ON tv.ticket_code = t.code
            WHERE t.event_id = :event_id
            AND o.order_status_id = 1
            """)

            params = {'event_id': event_id}

            if search:
                base_query = text(str(
                    base_query) + " AND (LOWER(t.customer_name) LIKE LOWER(:search) OR LOWER(t.customer_email) LIKE LOWER(:search))")
                count_query = text(str(
                    count_query) + " AND (LOWER(t.customer_name) LIKE LOWER(:search) OR LOWER(t.customer_email) LIKE LOWER(:search))")
                params['search'] = f"%{search}%"

            if ticket_type:
                base_query = text(str(base_query) +
                                  " AND tc.name = :ticket_type")
                count_query = text(str(count_query) +
                                   " AND tc.name = :ticket_type")
                params['ticket_type'] = ticket_type

            if offline is not None:
                base_query = text(str(base_query) +
                                  (" AND o.entry_by != 'anonymous'" if offline else " AND o.entry_by = 'anonymous'"))
                count_query = text(str(count_query) +
                                   (" AND o.entry_by != 'anonymous'" if offline else " AND o.entry_by = 'anonymous'"))

            if verified is not None:
                base_query = text(str(
                    base_query) + (" AND tv.scanned_at is not null" if verified else " AND tv.scanned_at is null"))
                count_query = text(str(
                    count_query) + (" AND tv.scanned_at is not null" if verified else " AND tv.scanned_at is null"))

                params['verified'] = 1 if verified else 0

            base_query = text(str(base_query) + """
                GROUP BY 
                    o.id, t.id, tv.id, o.order_status_id, tc.name, tc.price, t2.created_at,
                    u.address, tv.hash, o.entry_by, u2.name, tv.scanned_at, tv.un_scanned_at,
                    tv.scanned_by, tv.un_scanned_by, t.customer_email, t.customer_name, 
                    t.customer_gender, t.customer_phone_number, tc.id, t.order_id
                """)

            if verified is False:
                order_by_clause = " ORDER BY t.customer_name"
            elif verified is True:
                order_by_clause = " ORDER BY tv.scanned_at IS NULL DESC"
            else:
                order_by_clause = " ORDER BY t2.created_at, t.customer_email"

            base_query = text(str(base_query) + order_by_clause +
                              " LIMIT :page_size OFFSET :offset")
            params.update({'page_size': page_size, 'offset': offset})

            # Execute queries
            result_proxy = await conn.execute(base_query, params)
            data = result_proxy.mappings().all()

            count_result = await conn.execute(count_query, params)
            total_records = count_result.scalar()

            total_pages = (total_records + page_size - 1) // page_size

            formatted_data = [
                {
                    "address": row["fullAddress"],
                    "name": row["name"],
                    "email": row["email"],
                    "gender": row["gender"],
                    "id": row["id"],
                    "orderId": row["orderId"],
                    "entryBy": row["entryBy"],
                    "phoneNumber": row["phone"],
                    "birthDate": row["birthDate"],
                    "citizenId": row["citizenId"],
                    "emergencyCallName": row["emergencyCallName"],
                    "emergencyCallNumber": row["emergencyCallNumber"],
                    "ticketId": row["ticketId"],
                    "verifiedAt": row["verifiedAt"],
                    "ticket": {
                        "id": row["ticketId"],
                        "name": row["ticketName"],
                        "eventId": event_id,
                        "price": row["ticketPrice"]
                    },
                    "eventId": event_id,
                    "orderCreatedAt": row["orderCreatedAt"],
                    "isScanned": bool(row["isVerified"]),
                    "hash": row["hash"],
                    "ticketCount": row["ticketCount"],
                    "ticketNum": row["ticketNum"],
                    "verifiedBy": {
                        "id": row["verifiedById"],
                        "name": row["verifiedByName"],
                    },
                    "isHide": False
                } for row in data
            ]

        formatted_data = assign_gender_rank(formatted_data)

        return {
            "status": "SUCCESS",
            "message": "okay",
            "data": {
                "tickets": formatted_data,
                "pagination": {
                    "totalRecords": total_records,
                    "totalPages": total_pages,
                    "currentPage": page,
                    "pageSize": page_size
                },
            }
        }
    except Exception as e:
        print(e)
        response.status_code = 500
        return {"success": False, "error": str(e)}


db1 = 'kartjis_old_db'
db2 = 'event_commitee_kartjis'

# LOGIN


class LoginData(BaseModel):
    username: str
    password: str

# Fungsi untuk membuat token JWT


def create_token(user_data: dict):
    expiration = datetime.utcnow() + timedelta(days=7)
    payload = {**user_data, "exp": expiration}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# Fungsi untuk mengambil user dari token


async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Endpoint login yang menghasilkan token


async def loginOld(login_data: LoginData, response: Response):
    try:

        async with online_engine2.begin() as conn:
            fetch_query = f"""
            SELECT id, username, password, isAdmin, eventId, name, email
            FROM {db2}.users WHERE username = :username
            """

            result = await conn.execute(text(fetch_query), {"username": login_data.username})

            user = result.fetchone()
            print(user)

            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            if not bcrypt.checkpw(login_data.password.encode('utf-8'), user.password.encode('utf-8')):
                raise HTTPException(
                    status_code=401, detail="Invalid credentials")

            # Buat token JWT yang menyimpan eventId
            token = create_token({
                "username": user.username,
                "eventId": user.eventId
            })

            return {
                "status": "SUCCESS",
                "message": "Login successful",
                "data": {
                    "userId": user.id,
                    "username": user.username,
                    "isAdmin": user.isAdmin == 1,
                    "eventId": user.eventId,
                    "name": user.name,
                    "email": user.email,
                    "token": token
                }
            }
    except HTTPException as e:
        response.status_code = e.status_code
        return {"success": False, "error": e.detail}
    except Exception as e:
        print(e)
        response.status_code = 500
        return {"success": False, "error": "An internal server error occurred"}


# # GEt ORDERS
# @ticket.get('/api/events/orders')
async def read_orders_old(
    response: Response,
    search: str = Query(default=None, description="Search by name or email"),
    user: dict = Depends(get_current_user)  # Ambil user dari token
):
    try:
        event_id = user["eventId"]  # Ambil eventId dari token

        async with online_engine2.begin() as conn:
            base_query = f"""
            SELECT od.address as address, od.birthDate as birthDate,
            od.email AS email, od.gender as gender, od.id as id,
            od.location as location, od.NAME AS name, o.id as orderId, od.phoneNumber as phoneNumber,
            od.socialMedia as socialMedia,
            t.id as ticketId, t.name as ticketName, t.price as ticketPrice,
            o.createdAt as orderCreatedAt,
            tv.hash AS hash, tv.isScanned AS isVerified, tv.id as tvId, tv.updatedAt as verifiedAt,
            ROW_NUMBER() OVER (PARTITION BY od.orderId ORDER BY od.NAME) AS ticketNum, tv.verifiedBy,
            COUNT(*) OVER (PARTITION BY od.orderId) AS ticketCount,
            u.id AS verifiedById, u.name AS verifiedByName
            FROM {db1}.TicketVerification AS tv
            INNER JOIN {db1}.orderDetails AS od ON tv.orderDetailId=od.id
            INNER JOIN {db1}.tickets AS t ON od.ticketId=t.id
            INNER JOIN {db1}.orders o ON od.orderId = o.id
            LEFT JOIN {db2}.users u ON tv.verifiedBy = u.id
            WHERE t.eventId = :event_id and o.status = "SUCCESS"
            """

            params = {'event_id': event_id}
            if search:
                base_query += " AND (LOWER(od.name) LIKE LOWER(:search) OR LOWER(od.email) LIKE LOWER(:search))"
                params['search'] = f"%{search}%"

            base_query += " ORDER BY od.NAME"

            result_proxy = await conn.execute(text(base_query), params)
            data = result_proxy.fetchall()

            formatted_data = []
            for row in data:
                row_dict = dict(row)
                formatted_row = {
                    "address": row_dict["address"],
                    "name": row_dict["name"],
                    "birthDate": row_dict["birthDate"],
                    "email": row_dict["email"],
                    "gender": row_dict["gender"],
                    "id": row_dict["id"],
                    "commiteeName": "",
                    "orderId": row_dict["orderId"],
                    "phoneNumber": row_dict["phoneNumber"],
                    "socialMedia": row_dict["socialMedia"],
                    "ticketId": row_dict["ticketId"],
                    "verifiedAt": row_dict["verifiedAt"],
                    "ticket": {
                        "id": row_dict["ticketId"],
                        "name": row_dict["ticketName"],
                        "eventId": event_id,
                        "price": row_dict["ticketPrice"]
                    },
                    "eventId": event_id,
                    "orderCreatedAt": row_dict["orderCreatedAt"],
                    "isScanned": bool(row_dict["isVerified"]),
                    "hash": row_dict["hash"],
                    "ticketCount": row_dict["ticketCount"],
                    "ticketNum": row_dict["ticketNum"],
                    "verifiedBy": {
                        "id": row_dict.get("verifiedById"),
                        "name": row_dict.get("verifiedByName"),
                    },
                    "isHide": False
                }

                formatted_data.append(formatted_row)

        return {
            "status": "SUCCESS",
            "data": formatted_data
        }

    except Exception as e:
        response.status_code = 500
        return {"success": False, "error": str(e)}


async def ticket_type_summary_old(
    response: Response,
    user: dict = Depends(get_current_user)  # Ambil user dari token
):
    try:
        event_id = user["eventId"]
        async with online_engine2.begin() as conn:

            summary_query = f"""
            SELECT
                t.name AS ticketTypeName,
                COALESCE(COUNT(od.id), 0) AS totalSold,
                COALESCE(SUM(CASE WHEN od.gender = 'Male' THEN 1 ELSE 0 END), 0) AS maleCount,
                COALESCE(SUM(CASE WHEN od.gender = 'Female' THEN 1 ELSE 0 END), 0) AS femaleCount,
                t.price AS ticketPrice,
                t.stock AS stock,
                t.adminFee AS adminFee,
                COALESCE(t.price * COUNT(od.id), 0) AS totalPrice,
                COALESCE((t.price * COUNT(od.id)) + (COUNT(od.id) * t.adminFee), 0) AS revenueAfterAdminFee,
                COALESCE(SUM(CASE WHEN tv.isScanned = 1 THEN 1 ELSE 0 END), 0) AS verifiedCount,
                COALESCE(SUM(CASE WHEN tv.isScanned = 0 THEN 1 ELSE 0 END), 0) AS unverifiedCount
            FROM {db1}.tickets AS t
            LEFT JOIN {db1}.orderDetails AS od ON od.ticketId = t.id
            LEFT JOIN {db1}.orders AS o ON od.orderId = o.id AND o.status = 'SUCCESS'
            LEFT JOIN {db1}.TicketVerification tv ON tv.orderDetailId = od.id
            WHERE t.eventId = :event_id 
                AND o.status = 'SUCCESS'
            GROUP BY t.id
            ORDER BY t.name;
            """

            params = {'event_id': event_id}
            result_proxy = await conn.execute(text(summary_query), params)
            data = result_proxy.fetchall()

            ticket_counts = [
                {
                    "ticketTypeName": row["ticketTypeName"],
                    "totalSold": row["totalSold"],
                    "maleCount": row["maleCount"],
                    "femaleCount": row["femaleCount"],
                    "ticketPrice": row["ticketPrice"],
                    "totalPrice": row["totalPrice"],
                    "adminFee": row["adminFee"],
                    "stock": row["stock"],
                    "revenueAfterAdminFee": row["revenueAfterAdminFee"],
                    "verifiedCount": row["verifiedCount"],
                    "unverifiedCount": row["unverifiedCount"],
                }
                for row in data
            ]

            # Hitung summary keseluruhan
            total_tickets = sum(row["totalSold"] for row in data)
            total_verified = sum(row["verifiedCount"] for row in data)
            total_unverified = sum(row["unverifiedCount"] for row in data)

            ticket_summary = {
                "total": total_tickets,
                "verifiedCount": total_verified,
                "unverifiedCount": total_unverified
            }

            return {
                "status": "SUCCESS",
                "data": {
                    "ticketSummary": ticket_summary,
                    "ticketCounts": ticket_counts
                }
            }

    except Exception as e:
        response.status_code = 500  # Internal Server Error
        return {
            "success": False,
            "error": str(e),
        }


# @ticket.delete('/api/orders/{id}')
# async def delete_order(id: str, response: Response):
#     try:
#         async with online_engine2.begin() as conn:
#             # Delete query
#             delete_query = f"DELETE FROM {db1}.orders WHERE id = :id"
#             result = await conn.execute(text(delete_query), {'id': id})

#             # Check if any row was deleted
#             if result.rowcount == 0:
#                 raise HTTPException(status_code=404, detail="Order not found")

#         return {"status": "SUCCESS", "data": f"Order with ID {id} deleted successfully"}

#     except HTTPException as e:
#         raise e
#     except Exception as e:
#         print(e)
#         response.status_code = 500  # Internal Server Error
#         return {"status": "ERROR", "error": str(e)}


async def get_event_details_old(response: Response, user: dict = Depends(get_current_user)):
    event_id = user["eventId"]
    try:
        async with online_engine2.connect() as conn:
            event_query = f"""
            SELECT e.id as eventId, e.name as eventName,
                   t.id as ticketId, t.name as ticketName, t.price as ticketPrice
            FROM {db1}.events e
            LEFT JOIN {db1}.tickets t ON e.id = t.eventId
            WHERE e.id = :event_id
            """

            result = await conn.execute(text(event_query), {"event_id": event_id})
            rows = result.fetchall()

            if not rows:
                response.status_code = 404
                return {"status": "NOT_FOUND", "message": "Event not found"}

            # Extract event details
            event_data = {
                "id": rows[0]["eventId"],
                "banner": '',  # Placeholder for banner, update if necessary
                "name": rows[0]["eventName"],
                "tickets": [
                    {
                        "id": row["ticketId"],
                        "name": row["ticketName"],
                        "eventId": event_id,
                        "price": row["ticketPrice"]
                    } for row in rows if row["ticketId"]
                ]
            }

        return {
            "status": "SUCCESS",
            "data": event_data
        }

    except Exception as e:
        print(e)
        response.status_code = 500  # Internal Server Error
        return {
            "status": "ERROR",
            "message": str(e)}


# # GET EO
async def get_event_organizers_old(response: Response, user: dict = Depends(get_current_user)):
    try:
        eventId = user["eventId"]
        async with online_engine2.begin() as conn:
            # Query untuk mendapatkan semua event organizers berdasarkan eventId
            fetch_query = f"""
            SELECT
                eo.id as id,
                eo.username as username,
                eo.name as name,
                eo.email as email,
                eo.isAdmin as isAdmin,
                COUNT(tv.id) AS totalVerification
            FROM {db2}.users eo
            left JOIN {db1}.TicketVerification tv
                ON tv.verifiedBy = eo.id
            WHERE eo.eventId = :eventId
            GROUP BY eo.username, eo.name, eo.email, eo.isAdmin
        """

            result = await conn.execute(text(fetch_query), {"eventId": eventId})
            event_organizers = result.fetchall()

            if not event_organizers:
                raise HTTPException(
                    status_code=404, detail="No Event Organizers found for this event"
                )

            # Mengubah hasil query menjadi list of dictionaries
            organizers_list = [
                {
                    "id": organizer.id,
                    "username": organizer.username,
                    "name": organizer.name,
                    "email": organizer.email,  # Properti phone ditambahkan
                    "isAdmin": organizer.isAdmin == 1,
                    "totalVerification": organizer.totalVerification,
                }
                for organizer in event_organizers
            ]

            # Mengembalikan response sukses
            return {
                "status": "SUCCESS",
                "message": f"{len(organizers_list)} Event Organizer(s) fetched successfully",
                "data": organizers_list,
            }

    except HTTPException as e:
        response.status_code = e.status_code
        return {"success": False, "error": e.detail}
    except Exception as e:
        response.status_code = 500
        return {"success": False, "error": "An internal server error occurred"}


# # ADD TICKET


# @ticket.post('/api/tickets')
# async def create_ticket(ticket_data: TicketBase, response: Response, user: dict = Depends(get_current_user)):
#     try:
#         eventId = user["eventId"]
#         async with online_engine2.begin() as conn:
#             insert_query = f"""
#             INSERT INTO {db1}.tickets (name, price, stock, adminFee, eventId, id, updatedAt)
#             VALUES (:name, :price, :stock, :adminFee, :eventId, :id, :updatedAt)
#             """
#             params = {
#                 "name": ticket_data.name,
#                 "price": ticket_data.price,
#                 "stock": ticket_data.stock,
#                 "adminFee": 10000,
#                 "eventId": eventId,
#                 "id": uuid.uuid4(),
#                 "updatedAt": datetime.now(),
#             }

#             await conn.execute(text(insert_query), params)

#         return {"status": "SUCCESS", "message": "Ticket created successfully"}
#     except Exception as e:
#         print(e)
#         response.status_code = 500  # Internal Server Error
#         return {"success": False, "error": str(e)}

# # UODATE TICKEt


# @ticket.put('/api/tickets/{ticket_id}')
# async def update_ticket(ticket_id: str, ticket_data: TicketBase, response: Response):
#     try:
#         async with online_engine2.begin() as conn:
#             update_query = f"""
#             UPDATE {db1}.tickets
#             SET name = :name, price = :price, stock = :stock
#             WHERE id = :ticket_id
#             """
#             params = {
#                 "name": ticket_data.name,
#                 "price": ticket_data.price,
#                 "stock": ticket_data.stock,
#                 "ticket_id": ticket_id,
#             }

#             result = await conn.execute(text(update_query), params)

#             if result.rowcount == 0:
#                 response.status_code = 404  # Not Found
#                 return {"success": False, "message": "Ticket not found"}

#         return {"status": "SUCCESS", "message": "Ticket updated successfully"}
#     except Exception as e:
#         print(e)
#         response.status_code = 500  # Internal Server Error
#         return {"success": False, "error": str(e)}

# # VERIFY

@ticket.get('/api/events/orders3')
async def read_orders2(
    response: Response,
    search: Optional[str] = Query(None, description="Search by name or email"),
    ticket_type: Optional[str] = Query(
        None, description="Filter by ticket type"),
    verified: Optional[bool] = Query(
        None, description="Filter by verification status (true/false)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(
        50, ge=1, le=3000, description="Number of results per page"),
    offline: Optional[bool] = Query(
        None, description="Filter by offline online"),
    user: dict = Depends(get_current_user),
):
    try:
        event_id = user["eventId"]
        offset = (page - 1) * page_size

        async with online_engine.begin() as conn:
            base_query = text(f"""
with ticket_data as (SELECT 
    o.id AS "id",
    t.id AS "orderId",
    tv.id AS "tvId",
    o.order_status_id,
    tc.name AS "ticketName",
    tc.price AS "ticketPrice",
    t2.created_at AS "orderCreatedAt",
    u.address, 
    tv.hash AS "hash",
    o.entry_by AS "entryBy",
    u2.name AS "verifiedByName",
    CASE
        WHEN tv.scanned_at IS NULL THEN FALSE
        WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE
        ELSE TRUE
    END AS "isVerified",
    tv.scanned_at AS "verifieAt",
    tv.scanned_at AS "verified_at",
    tv.un_scanned_at AS "unverifiedAt",
    tv.scanned_by AS "verifiedById",
    tv.un_scanned_by AS "unverifiedBy",
    MAX(CASE WHEN tcf.name like '%Size Jersey%' THEN tcf.value END) AS "tshirtSize", 
    MAX(CASE WHEN tcf.name = 'Tanggal Lahir' THEN tcf.value END) AS "birthDate",
    MAX(CASE WHEN tcf.name = 'Nomor Telpon Kontak Darurat' THEN tcf.value END) AS "emergencyCallNumber",
    MAX(CASE WHEN tcf.name = 'Nama Kontak Darurat' THEN tcf.value END) AS "emergencyCallName",
    MAX(CASE WHEN tcf.name = 'Alamat Lengkap' THEN tcf.value END) AS "fullAddress",
    MAX(CASE WHEN tcf.name = 'No. KTP' THEN tcf.value END) AS "citizenId",
    ROW_NUMBER() OVER (PARTITION BY t.order_id ORDER BY t.id) AS "ticketNum",
    COUNT(*) OVER (PARTITION BY t.order_id) AS "ticketCount",
    t.customer_email AS "email",
    t.customer_name AS "name",
    t.customer_gender AS "gender",
    t.customer_phone_number AS "phone",
    tc.id AS "ticketId"
FROM orders o
JOIN tickets t ON t.order_id = o.id
JOIN transactions t2 ON t2.order_id = o.id  
JOIN ticket_verification tv ON tv.ticket_code = t.code 
LEFT JOIN users u2 ON u2.id = tv.scanned_by
LEFT JOIN ticket_categories tc ON tc.id = t.ticket_category_id
LEFT JOIN users u ON u.email = o.customer_id 
LEFT JOIN ticket_custom_fields tcf ON tcf.ticket_id = t.id
WHERE t.event_id = :event_id
  AND o.order_status_id = 1

            """)

            count_query = text(f"""
            SELECT COUNT(*)
            FROM orders o
            right JOIN tickets t ON t.order_id = o.id
            JOIN ticket_categories tc ON tc.id = t.ticket_category_id
            JOIN ticket_verification tv ON tv.ticket_code = t.code
            WHERE t.event_id = :event_id
            AND o.order_status_id = 1
            """)

            params = {'event_id': event_id}

            if search:
                base_query = text(str(
                    base_query) + " AND (LOWER(t.customer_name) LIKE LOWER(:search) OR LOWER(t.customer_email) LIKE LOWER(:search))")
                count_query = text(str(
                    count_query) + " AND (LOWER(t.customer_name) LIKE LOWER(:search) OR LOWER(t.customer_email) LIKE LOWER(:search))")
                params['search'] = f"%{search}%"

            if ticket_type:
                base_query = text(str(base_query) +
                                  " AND tc.id = :ticket_type")
                count_query = text(str(count_query) +
                                   " AND tc.id = :ticket_type")
                params['ticket_type'] = ticket_type

            if offline is not None:
                base_query = text(str(base_query) +
                                  (" AND o.entry_by != 'anonymous'" if offline else " AND o.entry_by = 'anonymous'"))
                count_query = text(str(count_query) +
                                   (" AND o.entry_by != 'anonymous'" if offline else " AND o.entry_by = 'anonymous'"))

            if verified is not None:
                base_query = text(str(
                    base_query) + (" AND tv.scanned_at is not null" if verified else " AND tv.scanned_at is null"))
                count_query = text(str(
                    count_query) + (" AND tv.scanned_at is not null" if verified else " AND tv.scanned_at is null"))

                params['verified'] = 1 if verified else 0

            base_query = text(str(base_query) + """
                GROUP BY 
                    o.id, t.id, tv.id, o.order_status_id, tc.name, tc.price, t2.created_at,
                    u.address, tv.hash, o.entry_by, u2.name, tv.scanned_at, tv.un_scanned_at,
                    tv.scanned_by, tv.un_scanned_by, t.customer_email, t.customer_name, 
                    t.customer_gender, t.customer_phone_number, tc.id, t.order_id)
                """)

            if verified is False:
                order_by_clause = " SELECT * FROM ticket_data ORDER BY name"
            elif verified is True:
                # Menggunakan alias yang benar
                order_by_clause = " SELECT * FROM ticket_data ORDER BY verified_at DESC"
            else:
                order_by_clause = " SELECT * FROM ticket_data ORDER BY orderCreatedAt, email"

            base_query = text(str(base_query) + order_by_clause +
                              " LIMIT :page_size OFFSET :offset")
            params.update({'page_size': page_size, 'offset': offset})

            # Execute queries
            result_proxy = await conn.execute(base_query, params)
            data = result_proxy.mappings().all()

            count_result = await conn.execute(count_query, params)
            total_records = count_result.scalar()

            total_pages = (total_records + page_size - 1) // page_size

            formatted_data = [
                {
                    "address": row["fullAddress"],
                    "name": row["name"],
                    "email": row["email"],
                    "gender": row["gender"],
                    "id": row["id"],
                    "orderId": row["orderId"],
                    "entryBy": row["entryBy"],
                    "phoneNumber": row["phone"],
                    "birthDate": row["birthDate"],
                    "citizenId": row["citizenId"],
                    "tshirtSize": row["tshirtSize"],
                    "emergencyCallName": row["emergencyCallName"],
                    "emergencyCallNumber": row["emergencyCallNumber"],
                    "ticketId": row["ticketId"],
                    "verifiedAt": row["verified_at"],
                    "ticket": {
                        "id": row["ticketId"],
                        "name": row["ticketName"],
                        "eventId": event_id,
                        "price": row["ticketPrice"]
                    },
                    "eventId": event_id,
                    "orderCreatedAt": row["orderCreatedAt"],
                    "isScanned": bool(row["isVerified"]),
                    "hash": row["hash"],
                    "ticketCount": row["ticketCount"],
                    "ticketNum": row["ticketNum"],
                    "verifiedBy": {
                        "id": row["verifiedById"],
                        "name": row["verifiedByName"],
                    },
                    "isHide": False,
                    "genderRank": None
                } for row in data
            ]

        # formatted_data = assign_gender_rank(formatted_data)

        return {
            "status": "SUCCESS",
            "message": "okay",
            "data": {
                "tickets": formatted_data,
                "pagination": {
                    "totalRecords": total_records,
                    "totalPages": total_pages,
                    "currentPage": page,
                    "pageSize": page_size
                },
            }
        }
    except Exception as e:
        print(e)
        response.status_code = 500
        return {"success": False, "error": str(e)}


# @ticket.put('/api/events/orders/{hash}')
async def update_verification_old(hash: str,  request: Request, response: Response, user: dict = Depends(get_current_user)):
    try:
        # Ambil data dari body request
        event_id = user["eventId"]
        body = await request.json()
        is_verify = body.get('isVerify')  # Mengambil nilai isVerify dari body
        verified_by = body.get('verifiedBy')  # ID user yang memverifikasi

        # Validasi body request
        if is_verify is None or not isinstance(is_verify, bool):
            response.status_code = 400  # Bad Request

            return {
                "success": False,
                "status": 'Failed',
                "code": '',
                "data": {
                    "code": "KARTJIS.44",
                    "detail": "'isVerify' harus berupa boolean."
                },
            }

        if not verified_by:
            response.status_code = 400  # Bad Request

            return {
                "success": False,
                "status": 'Failed',
                "code": '',
                "data": {
                    "code": "KARTJIS.44",
                    "detail": "'verifiedBy' tidak boleh kosong."
                },
            }

        # Set zona waktu lokal (misalnya waktu Makassar)
        local_tz = pytz.timezone("Asia/Makassar")
        current_datetime = datetime.now(local_tz)

        async with online_engine2.begin() as conn:
            # Query untuk memeriksa status tiket
            check_query = f"""
                SELECT od.address as address, od.birthDate as birthDate,
                od.email AS email, od.gender as gender, od.id as id,
                od.location as location, od.NAME AS name, o.id as orderId, od.phoneNumber as phoneNumber,
                od.socialMedia as socialMedia,
                t.id as ticketId, t.name as ticketName, t.price as ticketPrice,
                o.createdAt as orderCreatedAt,
                tv.hash AS hash, tv.isScanned AS isVerified, tv.id as tvId, tv.updatedAt as verifiedAt,
                ROW_NUMBER() OVER (PARTITION BY od.orderId ORDER BY od.NAME) AS ticketNum, tv.verifiedBy,
                COUNT(*) OVER (PARTITION BY od.orderId) AS ticketCount,
                u.id AS verifiedById, u.name AS verifiedByName
                FROM {db1}.TicketVerification AS tv
                INNER JOIN {db1}.orderDetails AS od ON tv.orderDetailId=od.id
                INNER JOIN {db1}.tickets AS t ON od.ticketId=t.id
                INNER JOIN {db1}.orders o ON od.orderId = o.id
                LEFT JOIN {db2}.users u ON tv.verifiedBy = u.id
                WHERE (tv.hash = :hash OR LOWER(t.id) = :hash) AND t.eventId = :event_id AND o.status = 'SUCCESS'
            """

            check_result = await conn.execute(text(check_query), {"hash": hash.lower(), "event_id": event_id})
            row_dict = check_result.fetchone()

            if not row_dict:
                response.status_code = 200  # Not Found
                return {
                    "success": False,
                    "status": 'Failed',
                    "code": '',
                    "data": {
                        "code": "KARTJIS.40",
                        "detail": "Kartjis tidak ditemukan."
                    },
                }

            # Ambil status verifikasi saat ini
            formatted_row = {
                "address": row_dict["address"],
                "name": row_dict["name"],
                "birthDate": None,
                "email": row_dict["email"],
                "gender": row_dict["gender"],
                "id": row_dict["id"],
                "commiteeName": "",
                "orderId": row_dict["orderId"],
                "phoneNumber": row_dict["phoneNumber"],
                "socialMedia": row_dict["socialMedia"],
                "ticketId": row_dict["ticketId"],
                "verifiedAt": None,
                "ticket": {
                    "id": row_dict["ticketId"],
                    "name": row_dict["ticketName"],
                    "eventId": event_id,
                    "price": row_dict["ticketPrice"]
                },
                "eventId": event_id,
                "orderCreatedAt": None,
                "isScanned": bool(row_dict["isVerified"]),
                "hash": row_dict["hash"],
                "ticketCount": row_dict["ticketCount"],
                "ticketNum": row_dict["ticketNum"],
                "verifiedBy": {
                    "id": row_dict["verifiedById"],
                    "name": row_dict["verifiedByName"],
                },
                "isHide": False,
                "citizenId": "",
                "emergencyCallName": "",
                "emergencyCallNumber": "",
                "genderRank": None,
                "entryBy": None,


            }

            if is_verify and bool(row_dict["isVerified"]):
                response.status_code = 200  # Bad Request
                return {
                    "success": False,
                    "status": 'Failed',
                    "code": '',
                    "data": {
                        "code": "KARTJIS.41",
                        "detail": "Kartjis sudah diverifikasi.",
                        "orderDetail": formatted_row,
                    }
                }

            # Update status verifikasi
            query_update = f"""
                UPDATE {db1}.TicketVerification AS tv
                INNER JOIN {db1}.orderDetails AS od ON tv.orderDetailId = od.id
                INNER JOIN {db1}.tickets AS t ON od.ticketId = t.id
                SET
                    tv.isScanned = :is_verify,
                    tv.updatedAt = :current_datetime,
                    tv.verifiedBy = :verified_by
                WHERE (tv.hash = :hash OR LOWER(t.id) = :hash)  AND t.eventId = :event_id
            """

            formatted_row['isScanned'] = True if is_verify else False
            formatted_row['verifiedAt'] = current_datetime

            await conn.execute(text(query_update), {
                "is_verify": 1 if is_verify else 0,
                "current_datetime": current_datetime,
                "verified_by": verified_by,
                "hash": hash.lower(),
                "event_id": event_id,
                "orderDetail": formatted_row,
            })

        # Response sukses

        return {
            "success": True,
            "status": 'SUCCEss',
            "code": '',
            "data": {
                "code": 'KARTJIS.21' if is_verify else "KARTJIS.20",
                "orderDetail": formatted_row,
                "detail": "Berhasil memverifikasi Kartjis." if is_verify else "Berhasil membatalkan verifikasi Kartjis."
            },
        }

    except HTTPException as http_error:
        # Tangani HTTPException
        raise http_error
    except Exception as e:
        response.status_code = 500  # Internal Server Error
        return {
            "success": False,
            "status": 'Failed',
            "code": '',
                    "data": {
                        "code": "KARTJIS.50",
                        "detail": "Terjadi kesalahan internal server."
                    }
        },


# # Add OTS
# @ticket.post('/api/events/offline-transactions')
# async def ots2(request: dict, response: Response,  user: dict = Depends(get_current_user)):
#     tickets = request.get("data", [])
#     event_id = user['eventId']
#     ordal = request.get('ordal', False)

#     async with online_engine2.begin() as conn:
#         try:
#             if len(tickets) <= 0:
#                 return
#             order_id = str(uuid.uuid4())
#             current_time = datetime.now()
#             customer_id = str(uuid.uuid4())
#             ticket1 = tickets[0]

#             await conn.execute(
#                 text(f"""
#                     INSERT INTO {db1}.customers (`id`, `name`, `email`, `birthDate`, `phoneNumber`, `gender`, `createdAt`, `updatedAt`)
#                     VALUES (:id, :name, :email, :birthDate, :phoneNumber, :gender, :createdAt, :updatedAt)
#                 """),
#                 {
#                     "id": customer_id,
#                     "name": ticket1["customer_name"],
#                     "email": ticket1["customer_email"],
#                     "birthDate": ticket1["customer_birthdate"],
#                     "phoneNumber": ticket1["customer_phone"],
#                     "gender": ticket1["customer_gender"],
#                     "createdAt": current_time,
#                     "updatedAt": current_time,
#                     "address": '',
#                 },
#             )

#             # Insert into `orders`
#             await conn.execute(
#                 text(f"""
#                     INSERT INTO {db1}.orders (`id`, `status`, `createdAt`, `updatedAt`, `customerId`, `eventId`)
#                     VALUES (:id, 'SUCCESS', :createdAt, :updatedAt, :customerId, :eventId)
#                 """),
#                 {
#                     "id": order_id,
#                     "createdAt": current_time,
#                     "updatedAt": current_time,
#                     "eventId": event_id,
#                     "customerId": customer_id
#                 },
#             )

#             # Insert into `customers`

#             for ticket in tickets:
#                 ticket_id = ticket["ticket_id"],
#                 order_detail_id = str(uuid.uuid4())
#                 verification_id = str(uuid.uuid4())

#                 result = await conn.execute(
#                     text(
#                         f"SELECT id FROM {
#                             db1}.tickets WHERE `id` = :id and `eventId` = :eventId"
#                     ),
#                     {"id": ticket_id, "eventId": event_id},
#                 )
#                 existing_ticket = result.fetchone()

#                 if existing_ticket:
#                     ticket_id = existing_ticket[0]
#                 else:
#                     await conn.execute(
#                         text(f"""
#                             INSERT INTO {db1}.tickets (`id`, `name`, `price`, `eventId`, `stock`, `createdAt`, `updatedAt`, `adminFee`)
#                             VALUES (:id, :name, :price, :eventId, :stock, :createdAt, :updatedAt, 0)
#                         """),
#                         {
#                             "id": ticket_id,
#                             "name": 'OTS',
#                             "price": 0,
#                             "eventId": event_id,
#                             "stock": 100,
#                             "createdAt": current_time,
#                             "updatedAt": current_time,
#                         },
#                     )

#                 # Insert into `orderdetails`
#                 await conn.execute(
#                     text(f"""
#                         INSERT INTO {db1}.orderDetails (`id`, `ticketId`, `quantity`, `orderId`, `name`, `email`, `birthDate`, `phoneNumber`, `gender`, `address`, `socialMedia`, `location`, `commiteeName`)
#                         VALUES (:id, :ticketId, 1, :orderId, :name, :email, :birthDate, :phoneNumber, :gender, :address, :socialMedia, :location, :commiteeName)
#                     """),
#                     {
#                         "id": order_detail_id,
#                         "ticketId": ticket_id,
#                         "orderId": order_id,
#                         "name": ticket["customer_name"],
#                         "email": ticket["customer_email"],
#                         "birthDate": ticket["customer_birthdate"],
#                         "phoneNumber": ticket["customer_phone"],
#                         "gender": ticket["customer_gender"],
#                         "address": ticket["address"],
#                         "socialMedia": ticket["social_media"],
#                         "location": '666' if ordal else None,
#                         "commiteeName": None,
#                     },
#                 )

#                 # Generate MD5 hash for ticket verification
#                 random_number = random.randint(1000, 9999)
#                 combined_string = f"{ticket['customer_email']}{
#                     order_detail_id}{current_time}{random_number}"
#                 hash_value = hashlib.md5(combined_string.encode()).hexdigest()

#                 await conn.execute(
#                     text(f"""
#                         INSERT INTO {db1}.TicketVerification (`id`, `hash`, `isScanned`, `createdAt`, `updatedAt`, `orderDetailId`)
#                         VALUES (:id, :hash, :isScanned, :createdAt, :updatedAt, :orderDetailId)
#                     """),
#                     {
#                         "id": verification_id,
#                         "hash": hash_value,
#                         "isScanned": 0 if ordal else 1,
#                         "createdAt": current_time,
#                         "updatedAt": current_time,
#                         "orderDetailId": order_detail_id,
#                     },
#                 )

#             return {
#                 "success": True,
#                 "data": "Tickets successfully created.",
#             }

#         except Exception as e:
#             print(e)
#             response.status_code = 500  # Internal Server Error
#             return {
#                 "success": False,
#                 "error": str(e),
#             }

# # Bom verification


# @ticket.put('/api/events/{event_id}/tickets/verifications')
# async def bulk_update_ticket_verifications(event_id: str, request: Request, response: Response):
#     try:
#         # Mengambil data dari body request
#         body = await request.json()
#         updates = body.get('data', [])  # List of updates

#         if not isinstance(updates, list) or not updates:
#             response.status_code = 400
#             return {"success": False, "message": "Invalid request body. 'verifications' must be a non-empty list."}

#         async with online_engine2.begin() as conn:
#             # Prepare update query
#             for verification in updates:
#                 hash_value = verification.get("hash")
#                 is_verify = verification.get("isVerify")
#                 verified_by_id = verification.get("verifiedById")

#                 if not hash_value or is_verify is None:
#                     continue  # Skip invalid entries

#                 # Set timezone to local
#                 local_tz = pytz.timezone("Asia/Makassar")
#                 current_datetime = datetime.now(local_tz)

#                 # Update query
#                 update_query = f"""
#                 UPDATE {db1}.TicketVerification AS tv
#                 INNER JOIN {db1}.orderDetails AS od ON tv.orderDetailId = od.id
#                 INNER JOIN {db1}.tickets AS t ON od.ticketId = t.id
#                 SET
#                     tv.isScanned = :is_verify,
#                     tv.updatedAt = :updated_at,
#                     tv.verifiedBy = :verified_by_id
#                 WHERE
#                     tv.hash = :hash_value
#                     AND t.eventId = :event_id
#                 """

#                 # Execute update
#                 await conn.execute(text(update_query), {
#                     "is_verify": 1 if is_verify else 0,
#                     "updated_at": current_datetime,
#                     "verified_by_id": verified_by_id,
#                     "hash_value": hash_value,
#                     "event_id": event_id,
#                 })

#         # Return response
#         return {
#             "success": True,
#             "message": "Bulk ticket verifications updated successfully."
#         }

#     except Exception as e:
#         print(e)
#         response.status_code = 500  # Internal Server Error
#         return {
#             "success": False,
#             "message": "An error occurred while processing the request.",
#             "error": str(e),
#         }

#     # Sync OTS


# @ticket.put('/api/events/{event_id}/sync-offline-transactions')
# async def sync_ots(request: dict, event_id: str, response: Response):
#     tickets = request.get("data", [])  # Mengambil array tiket dari key 'data'
#     async with online_engine2.begin() as conn:
#         try:
#             for ticket in tickets:
#                 # Diberikan di request body
#                 ticket_id = ticket.get("ticket_id")
#                 customer_id = uuid.uuid4()  # Fallback jika tidak ada
#                 order_id = ticket.get("order_id")  # Diberikan di request body
#                 # Diberikan di request body
#                 order_detail_id = ticket.get("order_detail_id")
#                 hash_value = ticket.get("hash")  # Diberikan di request body
#                 current_time = datetime.now()

#                 # Cek tiket yang ada di database
#                 result = await conn.execute(
#                     text(
#                         f"SELECT id FROM {
#                             db1}.tickets WHERE `id` = :id and `eventId` = :eventId"
#                     ),
#                     {"id": ticket_id, "eventId": event_id},
#                 )
#                 existing_ticket = result.fetchone()

#                 if existing_ticket:
#                     ticket_id = existing_ticket[0]
#                 else:
#                     return {
#                         "success": False,
#                         "error": str('ticket id required'),
#                     }
#                 # else:
#                 #     await conn.execute(
#                 #         text(f"""
#                 #             INSERT INTO {db1}.tickets (`id`, `name`, `price`, `eventId`, `stock`, `createdAt`, `updatedAt`, `adminFee`)
#                 #             VALUES (:id, :name, :price, :eventId, :stock, :createdAt, :updatedAt, 0)
#                 #         """),
#                 #         {
#                 #             "id": ticket_id,
#                 #             "name": 'OTS',
#                 #             "price": 0,
#                 #             "eventId": event_id,
#                 #             "stock": 100,
#                 #             "createdAt": current_time,
#                 #             "updatedAt": current_time,
#                 #         },
#                 #     )

#                 # Insert ke tabel `customers`
#                 await conn.execute(
#                     text(f"""
#                         INSERT INTO {db1}.customers (`id`, `name`, `email`, `birthDate`, `phoneNumber`, `gender`, `createdAt`, `updatedAt`)
#                         VALUES (:id, :name, :email, :birthDate, :phoneNumber, :gender, :createdAt, :updatedAt)
#                     """),
#                     {
#                         "id": customer_id,
#                         "name": ticket["customer_name"],
#                         "email": ticket["customer_email"],
#                         "birthDate": ticket["customer_birthdate"],
#                         "phoneNumber": ticket["customer_phone"],
#                         "gender": ticket["customer_gender"],
#                         "createdAt": current_time,
#                         "updatedAt": current_time,
#                     },
#                 )

#                 # Insert ke tabel `orders`
#                 await conn.execute(
#                     text(f"""
#                         INSERT INTO {db1}.orders (`id`, `status`, `createdAt`, `updatedAt`, `customerId`, `eventId`)
#                         VALUES (:id, 'SUCCESS', :createdAt, :updatedAt, :customerId, :eventId)
#                     """),
#                     {
#                         "id": order_id,
#                         "createdAt": current_time,
#                         "updatedAt": current_time,
#                         "customerId": customer_id,
#                         "eventId": event_id,
#                     },
#                 )

#                 # Insert ke tabel `orderdetails`
#                 await conn.execute(
#                     text(f"""
#                         INSERT INTO {db1}.orderDetails (`id`, `ticketId`, `quantity`, `orderId`, `name`, `email`, `birthDate`, `phoneNumber`, `gender`, `address`, `socialMedia`, `location`, `commiteeName`)
#                         VALUES (:id, :ticketId, 1, :orderId, :name, :email, :birthDate, :phoneNumber, :gender, :address, :socialMedia, :location, :commiteeName)
#                     """),
#                     {
#                         "id": order_detail_id,
#                         "ticketId": ticket_id,
#                         "orderId": order_id,
#                         "name": ticket["customer_name"],
#                         "email": ticket["customer_email"],
#                         "birthDate": ticket["customer_birthdate"],
#                         "phoneNumber": ticket["customer_phone"],
#                         "gender": ticket["customer_gender"],
#                         "address": ticket["address"],
#                         "socialMedia": ticket["social_media"],
#                         "location": None,
#                         "commiteeName": None,
#                     },
#                 )

#                 # Insert ke tabel `ticketverification`
#                 await conn.execute(
#                     text(f"""
#                         INSERT INTO {db1}.TicketVerification (`id`, `hash`, `isScanned`, `createdAt`, `updatedAt`, `orderDetailId`)
#                         VALUES (:id, :hash, 1, :createdAt, :updatedAt, :orderDetailId)
#                     """),
#                     {
#                         "id": str(uuid.uuid4()),
#                         "hash": hash_value,
#                         "createdAt": current_time,
#                         "updatedAt": current_time,
#                         "orderDetailId": order_detail_id,
#                     },
#                 )

#             return {
#                 "success": True,
#                 "message": "Tickets successfully synced.",
#             }

#         except Exception as e:
#             print(e)
#             response.status_code = 500  # Internal Server Error
#             return {
#                 "success": False,
#                 "error": str(e),
#             }


async def read_orders2(
    response: Response,
    search: Optional[str] = Query(None, description="Search by name or email"),
    ticket_type: Optional[str] = Query(
        None, description="Filter by ticket type"),
    verified: Optional[bool] = Query(
        None, description="Filter by verification status (true/false)"),

    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(
        50, ge=1, le=100, description="Number of results per page"),
    user: dict = Depends(get_current_user),
):
    try:
        event_id = user["eventId"]
        offset = (page - 1) * page_size

        async with online_engine2.begin() as conn:
            base_query = text(f"""
            SELECT od.address, od.birthDate, od.email, od.gender, od.id, od.location, od.NAME AS name,
                   o.id as orderId, od.phoneNumber, od.socialMedia, t.id as ticketId, t.name as ticketName, t.price as ticketPrice,
                   o.createdAt as orderCreatedAt, tv.hash, tv.isScanned AS isVerified, tv.id as tvId, tv.updatedAt as verifiedAt,
                   tv.verifiedBy, u.id AS verifiedById, u.name AS verifiedByName,
                   ROW_NUMBER() OVER (PARTITION BY od.orderId ORDER BY od.NAME) AS ticketNum,
                   COUNT(*) OVER (PARTITION BY od.orderId) AS ticketCount
            FROM {db1}.TicketVerification AS tv
            INNER JOIN {db1}.orderDetails AS od ON tv.orderDetailId = od.id
            INNER JOIN {db1}.tickets AS t ON od.ticketId = t.id
            INNER JOIN {db1}.orders o ON od.orderId = o.id
            LEFT JOIN {db2}.users u ON tv.verifiedBy = u.id
            WHERE t.eventId = :event_id 
                  AND o.status = 'SUCCESS'
            """)

            count_query = text(f"""
            SELECT COUNT(*)
            FROM {db1}.orders o
            INNER JOIN {db1}.orderDetails od ON o.id = od.orderId
            INNER JOIN {db1}.tickets t ON od.ticketId = t.id
            INNER JOIN {db1}.TicketVerification AS tv ON tv.orderDetailId = od.id
            WHERE t.eventId = :event_id 
                  AND o.status = 'SUCCESS'
            """)

            params = {'event_id': event_id}

            if search:
                base_query = text(str(
                    base_query) + " AND (LOWER(od.name) LIKE LOWER(:search) OR LOWER(od.email) LIKE LOWER(:search))")
                count_query = text(str(
                    count_query) + " AND (LOWER(od.name) LIKE LOWER(:search) OR LOWER(od.email) LIKE LOWER(:search))")
                params['search'] = f"%{search}%"

            if ticket_type:
                base_query = text(str(base_query) +
                                  " AND t.name = :ticket_type")
                count_query = text(str(count_query) +
                                   " AND t.name = :ticket_type")
                params['ticket_type'] = ticket_type

            if verified is not None:
                base_query = text(str(base_query) +
                                  " AND tv.isScanned = :verified")
                count_query = text(str(count_query) +
                                   " AND tv.isScanned = :verified")
                params['verified'] = 1 if verified else 0

            base_query = text(
                str(base_query) + " ORDER BY od.NAME LIMIT :page_size OFFSET :offset")
            params.update({'page_size': page_size, 'offset': offset})

            # Execute queries
            result_proxy = await conn.execute(base_query, params)
            data = result_proxy.mappings().all()

            count_result = await conn.execute(count_query, params)
            total_records = count_result.scalar()

            total_pages = (total_records + page_size - 1) // page_size

            formatted_data = [
                {
                    "address": row["address"],
                    "name": row["name"],
                    "birthDate": None,
                    "email": row["email"],
                    "gender": row["gender"],
                    "genderRank": None,
                    "entryBy": None,
                    "id": row["id"],
                    "citizenId": "",
                    "emergencyCallName": "",
                    "emergencyCallNumber": "",
                    "orderId": row["orderId"],
                    "phoneNumber": row["phoneNumber"],
                    "socialMedia": row["socialMedia"],
                    "ticketId": row["ticketId"],
                    "verifiedAt": row["verifiedAt"],
                    "ticket": {
                        "id": row["ticketId"],
                        "name": row["ticketName"],
                        "eventId": event_id,
                        "price": row["ticketPrice"]
                    },
                    "eventId": event_id,
                    "orderCreatedAt": None,
                    "isScanned": bool(row["isVerified"]),
                    "hash": row["hash"],
                    "ticketCount": row["ticketCount"],
                    "ticketNum": row["ticketNum"],
                    "verifiedBy": {
                        "id": row["verifiedById"],
                        "name": row["verifiedByName"],
                    },
                    "isHide": False
                } for row in data
            ]

        return {
            "status": "SUCCESS",
            "message": "okay",
            "data": {
                "tickets": formatted_data,
                "pagination": {
                    "totalRecords": total_records,
                    "totalPages": total_pages,
                    "currentPage": page,
                    "pageSize": page_size
                },
            }
        }
    except Exception as e:
        response.status_code = 500
        return {"success": False, "error": str(e)}


@ticket.get('/api/events/ticket-type-summary2')
async def ticket_type_summary(
    response: Response,
    user: dict = Depends(get_current_user)
):
    try:
        event_id = user["eventId"]
        async with online_engine.begin() as conn:
            summary_query = """
                SELECT
                    tc.id AS ticket_type_id,
                    tc.name AS ticket_type_name,
                    tc.staff_only,
                    tc.sales_end_time,
                    COALESCE(COUNT(od.id), 0) AS total_sold,
                    COALESCE(SUM(CASE WHEN od.customer_gender = 'MALE' THEN 1 ELSE 0 END), 0) AS male_count,
                    COALESCE(SUM(CASE WHEN od.customer_gender = 'FEMALE' THEN 1 ELSE 0 END), 0) AS female_count,
                    tc.price AS ticket_price,
                    tc.stock AS stock,
                    e.admin_fee AS admin_fee,
                    COALESCE(tc.price * COUNT(od.id), 0) AS total_price,
                    COALESCE((tc.price * COUNT(od.id)) + (COUNT(od.id) * e.admin_fee), 0) AS revenue_after_admin_fee,
                    COALESCE(SUM(CASE WHEN tv.scanned_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS verified_count,
                    COALESCE(SUM(CASE WHEN tv.scanned_at IS NULL THEN 1 ELSE 0 END), 0) AS unverified_count
                FROM ticket_categories AS tc
                LEFT JOIN tickets AS od ON od.ticket_category_id = tc.id
                LEFT JOIN orders AS o ON od.order_id = o.id
                LEFT JOIN ticket_verification tv ON tv.ticket_code = od.code
                LEFT JOIN events e ON e.id = od.event_id
                WHERE od.event_id = :event_id AND order_status_id = 1
                GROUP BY tc.id, tc.name, tc.staff_only, tc.sales_end_time, tc.price, tc.stock, e.admin_fee
                ORDER BY tc.name
            """

            params = {'event_id': event_id}
            result_proxy = await conn.execute(text(summary_query), params)
            data = result_proxy.fetchall()

        # --- Logic Python mengikuti Go ---
        prefix = "[generated] "
        grouped_by_name = {}

        for row in data:
            clean_name = row["ticket_type_name"] or ""
            if clean_name.lower().startswith(prefix.lower()):
                clean_name = clean_name[len(prefix):]

            # simpan versi cleaned name untuk grouping
            ticket = dict(row._mapping)
            ticket["ticket_type_name"] = clean_name

            lower_name = clean_name.lower()
            grouped_by_name.setdefault(lower_name, []).append(ticket)

        final_categories = []
        month_map = {
            1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "Mei", 6: "Jun",
            7: "Jul", 8: "Ags", 9: "Sep", 10: "Okt", 11: "Nov", 12: "Des"
        }

        for group in grouped_by_name.values():
            staff_status_count = {}
            for cat in group:
                staff_status_count[cat["staff_only"]] = staff_status_count.get(cat["staff_only"], 0) + 1

            has_staff = staff_status_count.get(True, 0) > 0
            has_nonstaff = staff_status_count.get(False, 0) > 0
            has_both = has_staff and has_nonstaff

            for cat in group:
                final_name = cat["ticket_type_name"]

                # Aturan 1: tambahkan (OFFLINE) jika ada staff & non-staff
                if has_both and cat["staff_only"]:
                    final_name = f"{final_name} (OFFLINE)"

                # Aturan 2: tambahkan tanggal jika duplikat di staffStatus yang sama
                if staff_status_count.get(cat["staff_only"], 0) > 1 and cat["sales_end_time"]:
                    try:
                        sales_end = cat["sales_end_time"]
                        if isinstance(sales_end, str):
                            from dateutil import parser
                            sales_end = parser.parse(sales_end)

                        date_str = f"{sales_end.day} {month_map[sales_end.month]}"
                        final_name = f"{final_name} ({date_str})"
                    except Exception:
                        pass

                cat["ticket_type_name"] = final_name
                final_categories.append(cat)

        # build response format
        ticket_counts = [
            {
                "ticketTypeName": row["ticket_type_name"],
                "ticketTypeId": row["ticket_type_id"],
                "totalSold": row["total_sold"] or 0,
                "maleCount": row["male_count"] or 0,
                "femaleCount": row["female_count"] or 0,
                "ticketPrice": row["ticket_price"] or 0,
                "totalPrice": row["total_price"] or 0,
                "adminFee": row["admin_fee"] or 0,
                "stock": row["stock"] or 0,
                "revenueAfterAdminFee": row["revenue_after_admin_fee"] or 0,
                "verifiedCount": row["verified_count"] or 0,
                "unverifiedCount": row["unverified_count"] or 0,
            }
            for row in final_categories
        ]

        ticket_summary = {
            "total": sum(row["totalSold"] for row in ticket_counts),
            "verifiedCount": sum(row["verifiedCount"] for row in ticket_counts),
            "unverifiedCount": sum(row["unverifiedCount"] for row in ticket_counts),
            "onlineRevenue": sum(row["totalPrice"] for row in ticket_counts),
            "offlineRevenue": 0,
        }

        return {
            "status": "SUCCESS",
            "data": {
                "ticketSummary": ticket_summary,
                "ticketCounts": ticket_counts
            }
        }

    except Exception as e:
        print("❌ Error:", e)
        response.status_code = 500
        return {"status": "ERROR", "error": str(e)}


def generate_slug(length=7):
    return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(length))


def md5_hash(text: str) -> str:
    return hashlib.md5(text.encode('utf-8')).hexdigest()

# Add OTS


@ticket.post('/api/events/offline-transactions2')
async def ots2(request: dict, response: Response, user: dict = Depends(get_current_user)):
    tickets = request.get("data", [])
    event_id = user['eventId']

    if not tickets:
        response.status_code = 400
        return {"success": False, "error": "No tickets provided"}

    async with online_engine.begin() as conn:  # type: AsyncConnection
        try:
            # Ambil kategori tiket dari tiket pertama (diasumsikan satu kategori)
            ticket_category_id = tickets[0]["ticket_id"]
            tc_result = await conn.execute(
                text(
                    "SELECT * FROM ticket_categories WHERE id = :id AND event_id = :eventId"),
                {"id": ticket_category_id, "eventId": event_id}
            )
            existing_ticket = tc_result.fetchone()
            if not existing_ticket:
                response.status_code = 404
                return {"success": False, "error": "Ticket category not found"}

            # Buat order
            order_id = generate_slug()
            current_time = datetime.now(timezone(timedelta(hours=8)))

            # total_amount = existing_ticket['price'] * len(tickets)
            # order_data = {
            #     "id": order_id,
            #     "date": current_time,
            #     "total_amount": total_amount,
            #     "admin_fees": 0,
            #     "entry_by": user['username'],
            #     "order_status_id": 1,
            #     "customer_id": tickets[0]['customer_email']
            # }

            # Buat order
            order_id = generate_slug()
            # Langsung pakai datetime
            current_time = datetime.now(timezone(timedelta(hours=8)))
            total_amount = existing_ticket['price'] * len(tickets)

            order_data = {
                "id": order_id,
                "date": current_time,  # langsung datetime, bukan string
                "total_amount": total_amount,
                "admin_fees": 0,
                "entry_by": user['username'],
                "order_status_id": 1,
                "customer_id": tickets[0]['customer_email']
            }

            await conn.execute(
                text("""
                    INSERT INTO orders (
                        id, date, total_amount, admin_fees,
                        entry_by, order_status_id, customer_id
                    ) VALUES (
                        :id, :date, :total_amount, :admin_fees,
                        :entry_by, :order_status_id, :customer_id
                    )
                """), order_data
            )

            # Setelah insert orders
            transaction_id = str(uuid.uuid4())

            await conn.execute(
                text("""
                    INSERT INTO transactions (
                        id, amount, date, order_id, source, created_at, updated_at, payment_type,transaction_status_id
                    ) VALUES (
                        :id, :amount, :date, :order_id, :source, :created_at, :updated_at, :payment_type,:transaction_status_id
                    )
                """),
                {
                    "id": transaction_id,
                    "transaction_status_id": 1,
                    "amount": total_amount,
                    "date": current_time,
                    "order_id": order_id,
                    "source": "Staff",  # bisa disesuaikan kalau perlu
                    "created_at": current_time,
                    "updated_at": current_time,
                    "payment_type": "OTC"
                },
            )

            # Set zona waktu lokal (misalnya waktu Makassar)
            local_tz = pytz.timezone("Asia/Makassar")
            aware_datetime = datetime.now(local_tz)

            # Convert to naive datetime, tapi dalam zona waktu Asia/Makassar
            current_datetime = aware_datetime.replace(tzinfo=None)

            # Insert setiap tiket
            for ticket in tickets:
                ticket_uuid = str(uuid.uuid4())
                code = generate_slug()
                ticket_data = {
                    "id": ticket_uuid,
                    "code": code,
                    "customer_email": ticket["customer_email"],
                    "customer_gender": ticket["customer_gender"],
                    "customer_name": ticket["customer_name"],
                    "event_id": event_id,
                    "order_id": order_id,
                    "ticket_category_id": ticket["ticket_id"],
                    "customer_phone_number": ticket["customer_phone"],
                    "price": existing_ticket['price']
                }

                await conn.execute(
                    text("""
                        INSERT INTO tickets (
                            id, code, customer_email, customer_gender,
                            customer_name, event_id, order_id,
                            ticket_category_id, customer_phone_number, price
                        ) VALUES (
                            :id, :code, :customer_email, :customer_gender,
                            :customer_name, :event_id, :order_id,
                            :ticket_category_id, :customer_phone_number, :price
                        )
                    """), ticket_data
                )

                # Insert ticket_verification
                await conn.execute(
                    text("""
                        INSERT INTO ticket_verification (
                            id, hash, ticket_code, ticket_id, scanned_at,
                    scanned_by
                        ) VALUES (
                            :id, :hash, :ticket_code, :ticket_id, :scanned_at, :scanned_by
                        )
                    """),
                    {
                        "id": str(uuid.uuid4()),
                        "hash": md5_hash(code),
                        "ticket_code": code,
                        "ticket_id": ticket_uuid,
                        "scanned_at": current_datetime,
                        "scanned_by": user['username'],
                    }
                )

            return {"success": True, "data": "Tickets successfully created."}

        except Exception as e:
            print(e)
            response.status_code = 500
            return {"success": False, "error": str(e)}


@ticket.get('/api/events/orders4')
async def read_orders2(
    response: Response,
    search: Optional[str] = Query(None, description="Search by name or email"),
    ticket_type: Optional[str] = Query(
        None, description="Filter by ticket type"),
    verified: Optional[bool] = Query(
        None, description="Filter by verification status (true/false)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(
        50, ge=1, le=3000, description="Number of results per page"),
    offline: Optional[bool] = Query(
        None, description="Filter by offline online"),
    user: dict = Depends(get_current_user),
):

    if (user["username"] == "kakimenapak"):
        return await read_orders2(
            response=response,
            search=search,
            ticket_type=ticket_type,
            verified=verified,
            page=page,
            page_size=page_size,
            user=user
        )
    try:
        event_id = user["eventId"]
        offset = (page - 1) * page_size

        async with online_engine.begin() as conn:
            base_query = text(f"""
SELECT
    o.id AS "id",
    t.id AS "orderId",
    tv.id AS "tvId",
    o.order_status_id,
    tc.name AS "ticketName",
    tc.price AS "ticketPrice",
    t2.created_at AS "orderCreatedAt",
    u.address,
    tv.hash AS "hash",
    o.entry_by AS "entryBy",
    u2.name AS "verifiedByName",
    CASE
        WHEN tv.scanned_at IS NULL THEN FALSE
        WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE
        ELSE TRUE
    END AS "isVerified",
    tv.scanned_at AS "verifiedAt",
    tv.un_scanned_at AS "unverifiedAt",
    tv.scanned_by AS "verifiedById",
    tv.un_scanned_by AS "unverifiedBy",
    MAX(CASE WHEN tcf.name like '%Baju%' THEN tcf.value END) AS "tshirtSize",
    MAX(CASE WHEN tcf.name = 'Tanggal Lahir' THEN tcf.value END) AS "birthDate",
    MAX(CASE WHEN tcf.name = 'Nomor Telpon Kontak Darurat' THEN tcf.value END) AS "emergencyCallNumber",
    MAX(CASE WHEN tcf.name = 'Nama Kontak Darurat' THEN tcf.value END) AS "emergencyCallName",
    MAX(CASE WHEN tcf.name = 'Alamat Lengkap' THEN tcf.value END) AS "fullAddress",
    MAX(CASE WHEN tcf.name = 'No. KTP' THEN tcf.value END) AS "citizenId",
    ROW_NUMBER() OVER (PARTITION BY t.order_id ORDER BY t.id) AS "ticketNum",
    COUNT(*) OVER (PARTITION BY t.order_id) AS "ticketCount",
    t.customer_email AS "email",
    t.customer_name AS "name",
    t.customer_gender AS "gender",
    t.customer_phone_number AS "phone",
    tc.id AS "ticketId"
FROM orders o
JOIN tickets t ON t.order_id = o.id
JOIN transactions t2 ON t2.order_id = o.id
JOIN ticket_verification tv ON tv.ticket_code = t.code
LEFT JOIN users u2 ON u2.id = tv.scanned_by
LEFT JOIN ticket_categories tc ON tc.id = t.ticket_category_id
LEFT JOIN users u ON u.email = o.customer_id
LEFT JOIN ticket_custom_fields tcf ON tcf.ticket_id = t.id
WHERE t.event_id = :event_id
  AND o.order_status_id = 1

            """)

            count_query = text(f"""
            SELECT COUNT(*)
            FROM orders o
            right JOIN tickets t ON t.order_id = o.id
            JOIN ticket_categories tc ON tc.id = t.ticket_category_id
            JOIN ticket_verification tv ON tv.ticket_code = t.code
            WHERE t.event_id = :event_id
            AND o.order_status_id = 1
            """)

            params = {'event_id': event_id}

            if search:
                base_query = text(str(
                    base_query) + " AND (LOWER(t.customer_name) LIKE LOWER(:search) OR LOWER(t.customer_email) LIKE LOWER(:search))")
                count_query = text(str(
                    count_query) + " AND (LOWER(t.customer_name) LIKE LOWER(:search) OR LOWER(t.customer_email) LIKE LOWER(:search))")
                params['search'] = f"%{search}%"

            if ticket_type:
                base_query = text(str(base_query) +
                                  " AND tc.name = :ticket_type")
                count_query = text(str(count_query) +
                                   " AND tc.name = :ticket_type")
                params['ticket_type'] = ticket_type

            if offline is not None:
                base_query = text(str(base_query) +
                                  (" AND o.entry_by != 'anonymous'" if offline else " AND o.entry_by = 'anonymous'"))
                count_query = text(str(count_query) +
                                   (" AND o.entry_by != 'anonymous'" if offline else " AND o.entry_by = 'anonymous'"))

            if verified is not None:
                base_query = text(str(
                    base_query) + (" AND tv.scanned_at is not null" if verified else " AND tv.scanned_at is null"))
                count_query = text(str(
                    count_query) + (" AND tv.scanned_at is not null" if verified else " AND tv.scanned_at is null"))

                params['verified'] = 1 if verified else 0

            base_query = text(str(base_query) + """
                GROUP BY
                    o.id, t.id, tv.id, o.order_status_id, tc.name, tc.price, t2.created_at,
                    u.address, tv.hash, o.entry_by, u2.name, tv.scanned_at, tv.un_scanned_at,
                    tv.scanned_by, tv.un_scanned_by, t.customer_email, t.customer_name,
                    t.customer_gender, t.customer_phone_number, tc.id, t.order_id
                """)

            if verified is False:
                order_by_clause = " ORDER BY t.customer_name"
            elif verified is True:
                order_by_clause = " ORDER BY tv.scanned_at IS NULL DESC"
            else:
                order_by_clause = " ORDER BY t2.created_at, t.customer_email"

            base_query = text(str(base_query) + order_by_clause +
                              " LIMIT :page_size OFFSET :offset")
            params.update({'page_size': page_size, 'offset': offset})

            # Execute queries
            result_proxy = await conn.execute(base_query, params)
            data = result_proxy.mappings().all()

            count_result = await conn.execute(count_query, params)
            total_records = count_result.scalar()

            total_pages = (total_records + page_size - 1) // page_size

            formatted_data = [
                {
                    "address": row["fullAddress"],
                    "name": row["name"],
                    "email": row["email"],
                    "gender": row["gender"],
                    "id": row["id"],
                    "tshirtSize" : row["tshirtSize"],
                    "orderId": row["orderId"],
                    "entryBy": row["entryBy"],
                    "phoneNumber": row["phone"],
                    "birthDate": row["birthDate"],
                    "citizenId": row["citizenId"],
                    "emergencyCallName": row["emergencyCallName"],
                    "emergencyCallNumber": row["emergencyCallNumber"],
                    "ticketId": row["ticketId"],
                    "verifiedAt": row["verifiedAt"],
                    "ticket": {
                        "id": row["ticketId"],
                        "name": row["ticketName"],
                        "eventId": event_id,
                        "price": row["ticketPrice"]
                    },
                    "eventId": event_id,
                    "orderCreatedAt": row["orderCreatedAt"],
                    "isScanned": bool(row["isVerified"]),
                    "hash": row["hash"],
                    "ticketCount": row["ticketCount"],
                    "ticketNum": row["ticketNum"],
                    "verifiedBy": {
                        "id": row["verifiedById"],
                        "name": row["verifiedByName"],
                    },
                    "isHide": False
                } for row in data
            ]

        formatted_data = assign_gender_rank(formatted_data)

        return {
            "status": "SUCCESS",
            "message": "okay",
            "data": {
                "tickets": formatted_data,
                "pagination": {
                    "totalRecords": total_records,
                    "totalPages": total_pages,
                    "currentPage": page,
                    "pageSize": page_size
                },
            }
        }
    except Exception as e:
        print(e)
        response.status_code = 500
        return {"success": False, "error": str(e)}


@ticket.get('/api/events/orders5')
async def read_orders4(
    response: Response,
    search: Optional[str] = Query(None, description="Search by name or email"),
    ticket_type: Optional[str] = Query(None, description="Filter by ticket type"),
    verified: Optional[bool] = Query(None, description="Filter by verification status (true/false)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=3000, description="Number of results per page"),
    offline: Optional[bool] = Query(None, description="Filter by offline online"),
    last_sync_at: Optional[datetime] = Query(None, description="Filter by last sync status (date time)"),
    user: dict = Depends(get_current_user),
):
    try:
        event_id = user["eventId"]
        offset = (page - 1) * page_size

        local_tz = pytz.timezone("Asia/Makassar")
        today_date_obj = datetime.now(local_tz).date()

        async with online_engine.begin() as conn:
            # === LANGKAH 1: Bangun semua filter dan jalankan kueri COUNT ===
            
            # Kueri dasar untuk filter yang akan digunakan di COUNT dan GET IDs
            # Pastikan semua tabel yang diperlukan untuk filter di-JOIN di sini
            filter_query_base = """
                FROM orders o
                JOIN tickets t ON t.order_id = o.id
                JOIN transactions t2 ON t2.order_id = o.id
                JOIN ticket_categories tc ON tc.id = t.ticket_category_id
                JOIN ticket_verification tv ON tv.ticket_code = t.code
                WHERE t.event_id = :event_id AND o.order_status_id = 1
            """
            params = {'event_id': event_id, 'today_date': today_date_obj}

            # Kumpulkan semua kondisi WHERE
            filter_conditions = []

            if search:
                filter_conditions.append("(LOWER(t.customer_name) LIKE LOWER(:search) OR LOWER(t.customer_email) LIKE LOWER(:search))")
                params['search'] = f"%{search}%"
            if ticket_type:
                filter_conditions.append("tc.id = :ticket_type")
                params['ticket_type'] = ticket_type
            if offline is not None:
                filter_conditions.append("o.entry_by != 'anonymous'" if offline else "o.entry_by = 'anonymous'")
            if last_sync_at:
                filter_conditions.append("(t2.created_at > :last_sync_at OR tv.scanned_at > :last_sync_at OR tv.un_scanned_at > :last_sync_at)")
                params['last_sync_at'] = last_sync_at

            # Tambahkan logika filter 'verified' yang kompleks di sini
            if verified is not None:
                is_verified_logic = """
                (CASE
                    WHEN tc.valid_from IS NOT NULL AND tc.valid_until IS NOT NULL AND CAST(tc.valid_until AS DATE) > CAST(tc.valid_from AS DATE) THEN
                        CASE
                            WHEN tv.scanned_at IS NOT NULL AND CAST(tv.scanned_at AS DATE) = CAST(:today_date AS DATE) THEN
                                CASE WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE ELSE TRUE END
                            ELSE FALSE
                        END
                    ELSE
                        CASE WHEN tv.scanned_at IS NULL THEN FALSE WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE ELSE TRUE END
                END)
                """
                filter_conditions.append(f"{is_verified_logic} = {'TRUE' if verified else 'FALSE'}")

            # Gabungkan semua filter
            if filter_conditions:
                filter_query_base += " AND " + " AND ".join(filter_conditions)
            
            # Eksekusi kueri hitung
            count_query = text(f"SELECT COUNT(DISTINCT t.id) {filter_query_base}")
            count_result = await conn.execute(count_query, params)
            total_records = count_result.scalar_one()
            total_pages = (total_records + page_size - 1) // page_size

            # === LANGKAH 2: Ambil HANYA ID Tiket untuk Halaman Saat Ini ===
            if verified is False:
                order_by_clause = "ORDER BY t.customer_name"
            elif verified is True:
                order_by_clause = "ORDER BY tv.scanned_at DESC"
            else:
                order_by_clause = "ORDER BY t2.created_at, t.customer_email"

            ids_query = text(f"""
                SELECT t.id 
                {filter_query_base}
                {order_by_clause}
                LIMIT :page_size OFFSET :offset
            """)
            
            ids_params = params.copy()
            ids_params.update({'page_size': page_size, 'offset': offset})
            
            ids_result = await conn.execute(ids_query, ids_params)
            ticket_ids = [row[0] for row in ids_result]

            formatted_data = []
            if ticket_ids:
                # === LANGKAH 3: Ambil Data Lengkap HANYA untuk ID yang Dipilih ===
                final_order_map = {id: i for i, id in enumerate(ticket_ids)}

                # Kueri berat ini sekarang berjalan pada set data yang sangat kecil dan aman.
                details_query = text("""
                    WITH ticket_data AS (
                        SELECT 
                            o.id AS "id", t.id AS "orderId", tv.id AS "tvId", o.order_status_id,
                            tc.name AS "ticketName", tc.price AS "ticketPrice",
                            tc.valid_from AS "validFrom", tc.valid_until AS "validUntil",
                            t2.created_at AS "orderCreatedAt", u.address, tv.hash AS "hash",
                            o.entry_by AS "entryBy", u2.name AS "verifiedByName",
                            CASE
                                WHEN tc.valid_from IS NOT NULL AND tc.valid_until IS NOT NULL AND CAST(tc.valid_until AS DATE) > CAST(tc.valid_from AS DATE) THEN
                                    CASE WHEN tv.scanned_at IS NOT NULL AND CAST(tv.scanned_at AS DATE) = CAST(:today_date AS DATE) THEN
                                        CASE WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE ELSE TRUE END
                                    ELSE FALSE END
                                ELSE
                                    CASE WHEN tv.scanned_at IS NULL THEN FALSE WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE ELSE TRUE END
                            END AS "isVerified",
                            tv.scanned_at AS "verified_at", tv.un_scanned_at AS "unverifiedAt",
                            tv.scanned_by AS "verifiedById", tv.un_scanned_by AS "unverifiedBy",
                            ROW_NUMBER() OVER (PARTITION BY t.order_id ORDER BY t.id) AS "ticketNum",
                            COUNT(*) OVER (PARTITION BY t.order_id) AS "ticketCount",
                            t.customer_email AS "email", t.customer_name AS "name",
                            t.customer_gender AS "gender", t.customer_phone_number AS "phone",
                            tc.id AS "ticketId"
                        FROM orders o
                        JOIN tickets t ON t.order_id = o.id
                        JOIN transactions t2 ON t2.order_id = o.id  
                        JOIN ticket_verification tv ON tv.ticket_code = t.code 
                        LEFT JOIN users u2 ON u2.id = tv.scanned_by
                        LEFT JOIN ticket_categories tc ON tc.id = t.ticket_category_id
                        LEFT JOIN users u ON u.email = o.customer_id 
                        LEFT JOIN ticket_custom_fields tcf ON tcf.ticket_id = t.id
                        WHERE t.id = ANY(:ticket_ids) -- KLAUSA PALING PENTING UNTUK EFISIENSI
                        GROUP BY 
                            o.id, t.id, tv.id, o.order_status_id, tc.name, tc.price, t2.created_at,
                            u.address, tv.hash, o.entry_by, u2.name, tv.scanned_at, tv.un_scanned_at,
                            tv.scanned_by, tv.un_scanned_by, t.customer_email, t.customer_name, 
                            t.customer_gender, t.customer_phone_number, tc.id, t.order_id,
                            tc.valid_from, tc.valid_until
                    )
                    SELECT * FROM ticket_data
                """)
                
                details_params = {'ticket_ids': ticket_ids, 'today_date': today_date_obj}
                result_proxy = await conn.execute(details_query, details_params)
                data = result_proxy.mappings().all()

                # Urutkan hasil di Python agar sesuai dengan urutan dari kueri ID
                data.sort(key=lambda row: final_order_map.get(row["orderId"], float('inf')))

                # Format data seperti sebelumnya
                formatted_data = [
                    {
                        "address": "", "name": row["name"], "email": row["email"],
                        "gender": row["gender"], "id": row["id"], "orderId": row["orderId"],
                        "entryBy": row["entryBy"], "phoneNumber": row["phone"], "birthDate": "",
                        "citizenId": "", "tshirtSize": "", "validFrom": row["validFrom"],
                        "validUntil": row["validUntil"], "emergencyCallName": "",
                        "emergencyCallNumber": "", "ticketId": row["ticketId"],
                        "verifiedAt": row["verified_at"],
                        "ticket": {
                            "id": row["ticketId"], "name": row["ticketName"], "eventId": event_id, "price": row["ticketPrice"]
                        },
                        "eventId": event_id, "orderCreatedAt": row["orderCreatedAt"],
                        "isScanned": bool(row["isVerified"]), "hash": row["hash"], "ticketCount": row["ticketCount"],
                        "ticketNum": row["ticketNum"],
                        "verifiedBy": { "id": row["verifiedById"], "name": row["verifiedByName"], },
                        "isHide": False, "genderRank": None
                    } for row in data
                ]

        return {
            "status": "SUCCESS", "message": "okay",
            "data": {
                "tickets": formatted_data,
                "pagination": { "totalRecords": total_records, "totalPages": total_pages, "currentPage": page, "pageSize": page_size },
            }
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        response.status_code = 500
        return {"success": False, "error": str(e)}


# Pastikan variabel-variabel ini sudah ada di file Anda
# from your_app import ticket, get_current_user, online_engine

# @ticket.put('/api/events/orders2/{hash}')
# async def update_verification(
#     hash: str,
#     request: Request,
#     response: Response,
#     user: dict = Depends(get_current_user),
# ):
#     try:
#         # 1. Ambil dan validasi data dari body request
#         event_id = user["eventId"]
#         body = await request.json()
#         is_verify = body.get('isVerify')
#         verified_by = body.get('verifiedBy')

#         if is_verify is None or not isinstance(is_verify, bool):
#             response.status_code = 400
#             return {
#                 "success": False,
#                 "status": 'Failed',
#                 "data": {
#                     "code": "KARTJIS.44",
#                     "detail": "'isVerify' harus berupa boolean."
#                 }
#             }

#         if not verified_by:
#             response.status_code = 400
#             return {
#                 "success": False,
#                 "status": 'Failed',
#                 "data": {
#                     "code": "KARTJIS.44",
#                     "detail": "'verifiedBy' tidak boleh kosong."
#                 }
#             }

#         # 2. Siapkan zona waktu dan waktu saat ini (WITA)
#         local_tz = pytz.timezone("Asia/Makassar")
#         aware_datetime_now = datetime.now(local_tz)
#         naive_datetime_for_db = aware_datetime_now.replace(tzinfo=None)

#         async with online_engine.begin() as conn:
#             # 3. Ambil detail tiket dari database
#             check_query = """
#                 SELECT 
#                     o.id AS "id",
#                     t.id AS "orderId",
#                     tv.id AS "tvId",
#                     o.order_status_id,
#                     tc.name AS "ticketName",
#                     tc.price AS "ticketPrice",
#                     tc.valid_from AS "validFrom",
#                     tc.valid_until AS "validUntil",
#                     t2.created_at AS "orderCreatedAt",
#                     tv.hash AS "hash",
#                     u2.name as "verifiedByName",
#                     tv.scanned_at IS NOT NULL AS "isVerified",
#                     tv.scanned_at AS "verifiedAt",
#                     tv.scanned_by AS "verifiedBy",
#                     ROW_NUMBER() OVER (PARTITION BY t.order_id ORDER BY t.id) AS "ticketNum",
#                     COALESCE(COUNT(*) OVER (PARTITION BY t.order_id), 0) AS "ticketCount",
#                     t.customer_email AS "email",
#                     t.customer_name AS "name",
#                     t.customer_gender AS "gender",
#                     t.customer_phone_number AS "phoneNumber",
#                     tc.id AS "ticketId"
#                 FROM orders o
#                 JOIN tickets t ON t.order_id = o.id
#                 JOIN transactions t2 ON t2.order_id = o.id  
#                 LEFT JOIN ticket_verification tv ON tv.ticket_code = t.code 
#                 LEFT JOIN users u2 on u2.id = tv.scanned_by
#                 LEFT JOIN ticket_categories tc ON tc.id = t.ticket_category_id
#                 WHERE (tv.hash = :hash OR tv.ticket_code = :hash)
#                   AND t.event_id = :event_id
#                   AND o.order_status_id = 1;
#             """
#             check_result = await conn.execute(
#                 text(check_query),
#                 {"hash": hash.lower(), "event_id": event_id},
#             )
#             row_dict = check_result.fetchone()

#             if not row_dict:
#                 response.status_code = 200
#                 return {
#                     "success": False,
#                     "status": 'Failed',
#                     "data": {
#                         "code": "KARTJIS.40",
#                         "detail": "Kartjis tidak ditemukan."
#                     }
#                 }

#             # Nilai sentinel (anggap null kalau dapat ini)
#             SENTINEL_DATETIME = datetime(2000, 1, 1, 1, 0, 0)

#             valid_from = row_dict["validFrom"]
#             now_date = aware_datetime_now.date()  # Tanggal hari ini di WITA

#             # --- VALID FROM ---
#             if valid_from:
#                 if isinstance(valid_from, datetime):
#                     if valid_from.tzinfo is not None:
#                         valid_from_in_local_tz = valid_from.astimezone(local_tz)
#                         valid_from_date = valid_from_in_local_tz.date()
#                         sentinel_date = SENTINEL_DATETIME.astimezone(local_tz).date()
#                     else:
#                         valid_from_date = valid_from.date()
#                         sentinel_date = SENTINEL_DATETIME.date()
#                 else:
#                     valid_from_date = valid_from
#                     sentinel_date = SENTINEL_DATETIME.date()

#                 # abaikan kalau sama dengan sentinel
#                 if valid_from_date != sentinel_date:
#                     if now_date < valid_from_date:
#                         response.status_code = 200
#                         return {
#                             "success": False,
#                             "status": 'Failed',
#                             "code": '',
#                             "data": {
#                                 "code": "KARTJIS.31",
#                                 "detail": "Kartjis belum aktif."
#                             },
#                         }

#             # --- VALID UNTIL ---
#             valid_until = row_dict["validUntil"]
#             if valid_until:
#                 if isinstance(valid_until, datetime):
#                     if valid_until.tzinfo is not None:
#                         valid_until_in_local_tz = valid_until.astimezone(local_tz)
#                         valid_until_date = valid_until_in_local_tz.date()
#                         sentinel_date = SENTINEL_DATETIME.astimezone(local_tz).date()
#                     else:
#                         valid_until_date = valid_until.date()
#                         sentinel_date = SENTINEL_DATETIME.date()
#                 else:
#                     valid_until_date = valid_until
#                     sentinel_date = SENTINEL_DATETIME.date()

#                 # abaikan kalau sama dengan sentinel
#                 if valid_until_date != sentinel_date:
#                     if now_date > valid_until_date:
#                         response.status_code = 200
#                         return {
#                             "success": False,
#                             "status": 'Failed',
#                             "code": '',
#                             "data": {
#                                 "code": "KARTJIS.32",
#                                 "detail": "Kartjis kadaluarsa."
#                             },
#                         }

#             # 5. Siapkan data respons awal
#             formatted_row = {
#                 "address": "",
#                 "name": row_dict["name"],
#                 "birthDate": "",
#                 "email": row_dict["email"],
#                 "gender": row_dict["gender"],
#                 "id": row_dict["id"],
#                 "commiteeName": "",
#                 "orderId": row_dict["orderId"],
#                 "phoneNumber": row_dict["phoneNumber"],
#                 "socialMedia": '',
#                 "ticketId": row_dict["ticketId"],
#                 "verifiedAt": row_dict["verifiedAt"],
#                 "eventId": event_id,
#                 "orderCreatedAt": row_dict["orderCreatedAt"],
#                 "isScanned": bool(row_dict["isVerified"]),
#                 "hash": row_dict["hash"],
#                 "ticketCount": row_dict["ticketCount"],
#                 "ticketNum": row_dict["ticketNum"],
#                 "isHide": False,
#                 "ticket": {
#                     "id": row_dict["ticketId"],
#                     "name": row_dict["ticketName"],
#                     "eventId": event_id,
#                     "price": row_dict["ticketPrice"],
#                 },
#                 "verifiedBy": {
#                     "id": row_dict["verifiedBy"],
#                     "name": row_dict["verifiedByName"],
#                 },
#             }

#             # 6. Logika untuk tiket yang sudah pernah di-scan
#             if is_verify and bool(row_dict["isVerified"]):
#                 allow_reverify = False
#                 if valid_from and valid_until:
#                     # Gunakan tanggal yang sudah dikonversi dengan benar
#                     if isinstance(valid_from, datetime):
#                         valid_from_date_check = (
#                             valid_from.astimezone(local_tz).date()
#                             if valid_from.tzinfo is not None
#                             else valid_from.date()
#                         )
#                     else:
#                         valid_from_date_check = valid_from

#                     if isinstance(valid_until, datetime):
#                         valid_until_date_check = (
#                             valid_until.astimezone(local_tz).date()
#                             if valid_until.tzinfo is not None
#                             else valid_until.date()
#                         )
#                     else:
#                         valid_until_date_check = valid_until

#                     if valid_until_date_check > valid_from_date_check:
#                         verified_at = row_dict["verifiedAt"]
#                         if verified_at:
#                             verified_at_in_local_tz = (
#                                 verified_at.astimezone(local_tz)
#                                 if verified_at.tzinfo is not None
#                                 else verified_at
#                             )
#                             if verified_at_in_local_tz.date() < now_date:
#                                 allow_reverify = True

#                 if not allow_reverify:
#                     response.status_code = 200
#                     return {
#                         "success": False,
#                         "status": 'Failed',
#                         "code": '',
#                         "data": {
#                             "code": "KARTJIS.41",
#                             "detail": "Kartjis sudah diverifikasi pada hari ini.",
#                             "orderDetail": formatted_row,
#                         },
#                     }

#             # 7. Update status verifikasi di database
#             query_update = """
#                 UPDATE ticket_verification SET
#                     scanned_at = :scanned_at,
#                     scanned_by = :scanned_by,
#                     un_scanned_at = :un_scanned_at,
#                     un_scanned_by = :un_scanned_by
#                 WHERE id = :tvId;
#             """
#             await conn.execute(
#                 text(query_update),
#                 {
#                     "scanned_at": naive_datetime_for_db if is_verify else None,
#                     "un_scanned_at": None if is_verify else naive_datetime_for_db,
#                     "scanned_by": verified_by if is_verify else None,
#                     "un_scanned_by": None if is_verify else verified_by,
#                     "tvId": row_dict["tvId"],
#                 },
#             )

#             # 8. Ambil data pendukung untuk respons akhir
#             user_name_result = await conn.execute(
#                 text("SELECT name FROM users WHERE id = :id"),
#                 {"id": verified_by},
#             )
#             verifier_user = user_name_result.fetchone()

#             # 9. Query tambahan untuk ambil tshirtSize & citizenId dari ticket_custom_fields
#             tshirt_query = """
#                 SELECT 
#                     value AS "tsize"
#                 FROM ticket_custom_fields
#                 WHERE ticket_id = :ticket_id and name LIKE '%Baju%';
#             """
#             tshirt_result = await conn.execute(
#                 text(tshirt_query),
#                 {"ticket_id": row_dict["orderId"]},
#             )
#             tshirt_row = tshirt_result.fetchone()
#             tshirt_data = dict(tshirt_row._mapping) if tshirt_row else {}

#             # 10. Lengkapi data respons dengan informasi terbaru
#             formatted_row["citizenId"] = ""
#             formatted_row["tshirtSize"] = tshirt_data.get("tsize", "") or ""
#             formatted_row["isScanned"] = is_verify
#             formatted_row["verifiedAt"] = naive_datetime_for_db if is_verify else None
#             formatted_row["verifiedBy"] = {
#                 "id": verified_by,
#                 "name": verifier_user["name"] if verifier_user else None,
#             }

#         # 11. Kirim respons sukses
#         return {
#             "success": True,
#             "status": 'SUCCESS',
#             "data": {
#                 "code": 'KARTJIS.21' if is_verify else "KARTJIS.20",
#                 "detail": "Berhasil memverifikasi Kartjis."
#                 if is_verify
#                 else "Berhasil membatalkan verifikasi Kartjis.",
#                 "orderDetail": formatted_row,
#             },
#         }

#     except HTTPException as http_error:
#         raise http_error
#     except Exception as e:
#         print(f"Internal server error: {e}")
#         response.status_code = 500
#         return {
#             "success": False,
#             "status": 'Failed',
#             "data": {
#                 "code": "KARTJIS.50",
#                 "detail": "Terjadi kesalahan internal server."
#             },
#         }


from datetime import datetime
import pytz
from fastapi import Depends, HTTPException
from fastapi import Request, Response
from sqlalchemy import text

# asumsi: online_engine, ticket (APIRouter), get_current_user sudah ada di modul Anda

@ticket.put('/api/events/orders2/{hash}')
async def update_verification(
    hash: str,
    request: Request,
    response: Response,
    user: dict = Depends(get_current_user),
):
    try:
        # 1) Ambil dan validasi body
        event_id = user["eventId"]
        body = await request.json()
        is_verify = body.get('isVerify')
        verified_by = body.get('verifiedBy')

        if is_verify is None or not isinstance(is_verify, bool):
            response.status_code = 400
            return {
                "success": False,
                "status": "Failed",
                "data": {"code": "KARTJIS.44", "detail": "'isVerify' harus berupa boolean."}
            }

        if not verified_by:
            response.status_code = 400
            return {
                "success": False,
                "status": "Failed",
                "data": {"code": "KARTJIS.44", "detail": "'verifiedBy' tidak boleh kosong."}
            }

        # 2) Waktu saat ini (WITA)
        local_tz = pytz.timezone("Asia/Makassar")
        aware_datetime_now = datetime.now(local_tz)
        naive_datetime_for_db = aware_datetime_now.replace(tzinfo=None)
        now_date = aware_datetime_now.date()
        hash_value = (hash or "").strip().lower()
        hash_pattern = f"%{hash_value}%"

        async with online_engine.begin() as conn:
            # 3) Ambil detail tiket (tanpa valid_from / valid_until)
            check_query = """
                SELECT 
                    o.id AS "id",
                    t.id AS "orderId",
                    tv.id AS "tvId",
                    o.order_status_id,
                    tc.name AS "ticketName",
                    tc.price AS "ticketPrice",
                    t2.created_at AS "orderCreatedAt",
                    tv.hash AS "hash",
                    u2.name as "verifiedByName",
                    tv.scanned_at IS NOT NULL AS "isVerified",
                    tv.scanned_at AS "verifiedAt",
                    tv.scanned_by AS "verifiedBy",
                    ROW_NUMBER() OVER (PARTITION BY t.order_id ORDER BY t.id) AS "ticketNum",
                    COALESCE(COUNT(*) OVER (PARTITION BY t.order_id), 0) AS "ticketCount",
                    t.customer_email AS "email",
                    t.customer_name AS "name",
                    t.customer_gender AS "gender",
                    t.customer_phone_number AS "phoneNumber",
                    tc.id AS "ticketId"
                FROM orders o
                JOIN tickets t ON t.order_id = o.id
                JOIN transactions t2 ON t2.order_id = o.id  
                LEFT JOIN ticket_verification tv ON tv.ticket_code = t.code 
                LEFT JOIN users u2 on u2.id = tv.scanned_by
                LEFT JOIN ticket_categories tc ON tc.id = t.ticket_category_id
                WHERE (
                        (tv.hash IS NOT NULL AND LOWER(tv.hash) LIKE :hash_pattern)
                        OR tv.ticket_code = :hash
                    )
                  AND t.event_id = :event_id
                  AND o.order_status_id = 1;
            """
            check_result = await conn.execute(
                text(check_query),
                {
                    "hash": hash_value,
                    "hash_pattern": hash_pattern,
                    "event_id": event_id,
                },
            )
            row = check_result.fetchone()

            if not row:
                response.status_code = 200
                return {
                    "success": False,
                    "status": "Failed",
                    "data": {"code": "KARTJIS.40", "detail": "Kartjis tidak ditemukan."}
                }

            row_dict = dict(row._mapping)

            # 4) Siapkan respons awal
            formatted_row = {
                "address": "",
                "name": row_dict["name"],
                "birthDate": "",
                "email": row_dict["email"],
                "gender": row_dict["gender"],
                "id": row_dict["id"],
                "commiteeName": "",
                "orderId": row_dict["orderId"],
                "phoneNumber": row_dict["phoneNumber"],
                "socialMedia": '',
                "ticketId": row_dict["ticketId"],
                "verifiedAt": row_dict["verifiedAt"],
                "eventId": event_id,
                "orderCreatedAt": row_dict["orderCreatedAt"],
                "isScanned": bool(row_dict["isVerified"]),
                "hash": row_dict["hash"],
                "ticketCount": row_dict["ticketCount"],
                "ticketNum": row_dict["ticketNum"],
                "isHide": False,
                "ticket": {
                    "id": row_dict["ticketId"],
                    "name": row_dict["ticketName"],
                    "eventId": event_id,
                    "price": row_dict["ticketPrice"],
                },
                "verifiedBy": {
                    "id": row_dict["verifiedBy"],
                    "name": row_dict["verifiedByName"],
                },
            }

            # 5) Aturan re-verify tanpa valid_from/valid_until:
            #    - Jika tiket sudah discan dan tanggal verifiedAt == hari ini (WITA) -> tolak.
            #    - Jika verifiedAt < hari ini -> izinkan verifikasi ulang.
            if is_verify and bool(row_dict["isVerified"]):
                allow_reverify = False
                verified_at = row_dict["verifiedAt"]
                if verified_at:
                    # verified_at dari DB bisa naive atau aware; sesuaikan ke WITA date
                    if isinstance(verified_at, datetime) and verified_at.tzinfo is not None:
                        verified_date_local = verified_at.astimezone(local_tz).date()
                    else:
                        # anggap naive, treat sebagai waktu server dan bandingkan tanggalnya saja
                        verified_date_local = verified_at.date()
                    if verified_date_local < now_date:
                        allow_reverify = False

                if not allow_reverify:
                    response.status_code = 200
                    return {
                        "success": False,
                        "status": "Failed",
                        "code": "",
                        "data": {
                            "code": "KARTJIS.41",
                            "detail": "Kartjis sudah diverifikasi pada hari ini.",
                            "orderDetail": formatted_row,
                        },
                    }

            # 6) Update status verifikasi
            query_update = """
                UPDATE ticket_verification SET
                    scanned_at = :scanned_at,
                    scanned_by = :scanned_by,
                    un_scanned_at = :un_scanned_at,
                    un_scanned_by = :un_scanned_by
                WHERE id = :tvId;
            """
            await conn.execute(
                text(query_update),
                {
                    "scanned_at": naive_datetime_for_db if is_verify else None,
                    "un_scanned_at": None if is_verify else naive_datetime_for_db,
                    "scanned_by": verified_by if is_verify else None,
                    "un_scanned_by": None if is_verify else verified_by,
                    "tvId": row_dict["tvId"],
                },
            )

            # 7) Ambil nama verifier terbaru
            user_name_result = await conn.execute(
                text("SELECT name FROM users WHERE id = :id"),
                {"id": verified_by},
            )
            verifier_user = user_name_result.fetchone()

            # 8) Ambil tshirtSize (tetap seperti versi Anda)
            tshirt_query = """
                SELECT value AS "tsize"
                FROM ticket_custom_fields
                WHERE ticket_id = :ticket_id AND name LIKE '%Baju%';
            """
            tshirt_result = await conn.execute(
                text(tshirt_query),
                {"ticket_id": row_dict["orderId"]},
            )
            tshirt_row = tshirt_result.fetchone()
            tshirt_data = dict(tshirt_row._mapping) if tshirt_row else {}

            # 9) Lengkapi respons akhir
            formatted_row["citizenId"] = ""
            formatted_row["tshirtSize"] = tshirt_data.get("tsize", "") or ""
            formatted_row["isScanned"] = is_verify
            formatted_row["verifiedAt"] = naive_datetime_for_db if is_verify else None
            formatted_row["verifiedBy"] = {
                "id": verified_by,
                "name": verifier_user["name"] if verifier_user else None,
            }

        # 10) Sukses
        return {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "code": "KARTJIS.21" if is_verify else "KARTJIS.20",
                "detail": "Berhasil memverifikasi Kartjis." if is_verify else "Berhasil membatalkan verifikasi Kartjis.",
                "orderDetail": formatted_row,
            },
        }

    except HTTPException as http_error:
        raise http_error
    except Exception as e:
        # iya, server juga bisa ngambek
        print(f"Internal server error: {e}")
        response.status_code = 500
        return {
            "success": False,
            "status": "Failed",
            "data": {"code": "KARTJIS.50", "detail": "Terjadi kesalahan internal server."},
        }



class TicketUpdate(BaseModel):
    hash: str
    update_timestamp: Optional[datetime] = None
    isVerify: bool



class SyncRequest(BaseModel):
    last_sync_at: Optional[datetime] = None
    list_update_tickets: List[TicketUpdate]


@ticket.post('/api/events/synchronize')
async def synchronize_tickets(
    response: Response,
    body: SyncRequest,
    page: int = Query(1, ge=1, description="Page number for initial sync"),
    page_size: int = Query(50, ge=1, le=3000, description="Results per page for initial sync"),
    user: dict = Depends(get_current_user),
):
    try:
        event_id = user["eventId"]
        username = user["username"]
        local_tz = pytz.timezone("Asia/Makassar")
        now = datetime.now(local_tz)
        today_date_obj = now.date()


        async with online_engine.begin() as conn:
            user_id_query = text("SELECT id FROM users WHERE username = :username LIMIT 1")
            result = await conn.execute(user_id_query, {"username": username})
            user_id = result.scalar_one_or_none()

            if not user_id:
                raise ValueError(f"User ID not found for username: {username}")
                
            # =================================================================
            # LANGKAH 1: PROSES UPDATE DARI KLIEN
            # =================================================================
            if body.list_update_tickets:
                for ticket_update in body.list_update_tickets:
                    timestamp_to_use = ticket_update.update_timestamp or now

                    if ticket_update.isVerify:
                        verify_query = text("""
                            UPDATE ticket_verification
                            SET 
                                scanned_at = :timestamp,
                                scanned_by = :user_id,
                                un_scanned_at = NULL,
                                un_scanned_by = NULL
                            WHERE hash = :hash
                        """)
                        await conn.execute(
                            verify_query,
                            {"timestamp": timestamp_to_use, "user_id": user_id, "hash": ticket_update.hash}
                        )
                    else:
                        unverify_query = text("""
                            UPDATE ticket_verification
                            SET
                                scanned_at = NULL,
                                scanned_by = NULL,
                                un_scanned_at = :timestamp,
                                un_scanned_by = :user_id
                            WHERE hash = :hash
                        """)
                        await conn.execute(
                            unverify_query,
                            {"timestamp": timestamp_to_use, "user_id": user_id, "hash": ticket_update.hash}
                        )

            # =================================================================
            # LANGKAH 2: AMBIL DATA YANG BERUBAH UNTUK DIKIRIM KE KLIEN
            # =================================================================
            filter_query_base = """
                FROM orders o
                JOIN tickets t ON t.order_id = o.id
                JOIN transactions t2 ON t2.order_id = o.id
                JOIN ticket_categories tc ON tc.id = t.ticket_category_id
                JOIN ticket_verification tv ON tv.ticket_code = t.code
                WHERE t.event_id = :event_id AND o.order_status_id = 1
            """

            params = {"event_id": event_id, "today_date": today_date_obj}
            is_initial_sync = body.last_sync_at is None

            if not is_initial_sync:
                filter_query_base += """
                    AND (
                        o.date > :last_sync_at OR 
                        tv.scanned_at > :last_sync_at OR 
                        tv.un_scanned_at > :last_sync_at
                    )
                """
                params["last_sync_at"] = body.last_sync_at

            excluded_hashes = [t.hash for t in body.list_update_tickets] if body.list_update_tickets else []
            if excluded_hashes:
                filter_query_base += " AND tv.hash != ALL(:excluded_hashes)"
                params["excluded_hashes"] = excluded_hashes

            # Hitung total record untuk initial sync
            total_records = 0
            total_pages = 0
            if is_initial_sync:
                count_query = text(f"SELECT COUNT(DISTINCT t.id) {filter_query_base}")
                count_result = await conn.execute(count_query, params)
                total_records = count_result.scalar_one()
                total_pages = (total_records + page_size - 1) // page_size

            # Ambil ID tiket yang relevan
            offset = (page - 1) * page_size
            limit_offset_clause = "LIMIT :page_size OFFSET :offset" if is_initial_sync else ""

            ids_query = text(f"""
                SELECT t.id 
                {filter_query_base}
                ORDER BY t2.created_at, t.customer_email
                {limit_offset_clause}
            """)

            ids_params = params.copy()
            if is_initial_sync:
                ids_params.update({"page_size": page_size, "offset": offset})

            ids_result = await conn.execute(ids_query, ids_params)
            ticket_ids = [row[0] for row in ids_result]

            

            formatted_data = []
            if ticket_ids:
                details_query = text("""
                    WITH ticket_data AS (
                        SELECT 
                            o.id AS "id", t.id AS "orderId", tv.id AS "tvId", o.order_status_id,
                            tc.name AS "ticketName", tc.price AS "ticketPrice",
                            tc.valid_from AS "validFrom", tc.valid_until AS "validUntil",
                            t2.created_at AS "orderCreatedAt", o.date AS "orderUpdatedAt",
                            u.address, tv.hash AS "hash",
                            o.entry_by AS "entryBy", u2.name AS "verifiedByName",
                            CASE
                                WHEN tc.valid_from IS NOT NULL AND tc.valid_until IS NOT NULL 
                                     AND CAST(tc.valid_until AS DATE) > CAST(tc.valid_from AS DATE)
                                THEN
                                    CASE 
                                        WHEN tv.scanned_at IS NOT NULL 
                                             AND CAST(tv.scanned_at AS DATE) = CAST(:today_date AS DATE) 
                                        THEN
                                            CASE 
                                                WHEN tv.un_scanned_at IS NOT NULL 
                                                     AND tv.un_scanned_at > tv.scanned_at 
                                                THEN FALSE 
                                                ELSE TRUE 
                                            END
                                        ELSE FALSE 
                                    END
                                ELSE
                                    CASE 
                                        WHEN tv.scanned_at IS NULL THEN FALSE 
                                        WHEN tv.un_scanned_at IS NOT NULL 
                                             AND tv.un_scanned_at > tv.scanned_at 
                                        THEN FALSE 
                                        ELSE TRUE 
                                    END
                            END AS "isVerified",
                            tv.scanned_at AS "verifiedAt", 
                            tv.un_scanned_at AS "unverifiedAt",
                            tv.scanned_by AS "verifiedById", 
                            tv.un_scanned_by AS "unverifiedBy",
                            ROW_NUMBER() OVER (PARTITION BY t.order_id ORDER BY t.id) AS "ticketNum",
                            COUNT(*) OVER (PARTITION BY t.order_id) AS "ticketCount",
                            t.customer_email AS "email", 
                            t.customer_name AS "name",
                            t.customer_gender AS "gender", 
                            t.customer_phone_number AS "phone",
                            tc.id AS "ticketId"
                        FROM orders o
                        JOIN tickets t ON t.order_id = o.id
                        JOIN transactions t2 ON t2.order_id = o.id  
                        JOIN ticket_verification tv ON tv.ticket_code = t.code 
                        LEFT JOIN users u2 ON u2.id = tv.scanned_by
                        LEFT JOIN ticket_categories tc ON tc.id = t.ticket_category_id
                        LEFT JOIN users u ON u.email = o.customer_id 
                        LEFT JOIN ticket_custom_fields tcf ON tcf.ticket_id = t.id
                        WHERE t.id = ANY(:ticket_ids)   
                        GROUP BY 
                            o.id, t.id, tv.id, o.order_status_id, tc.name, tc.price, t2.created_at,
                            u.address, tv.hash, o.entry_by, u2.name, tv.scanned_at, tv.un_scanned_at,
                            tv.scanned_by, tv.un_scanned_by, t.customer_email, t.customer_name, 
                            t.customer_gender, t.customer_phone_number, tc.id, t.order_id,
                            tc.valid_from, tc.valid_until
                    )
                    SELECT * FROM ticket_data
                """)

                details_params = {"ticket_ids": ticket_ids, "today_date": today_date_obj}
                result_proxy = await conn.execute(details_query, details_params)
                data = result_proxy.mappings().all()

                formatted_data = [
                    {
                        "name": row["name"],
                        "email": row["email"],
                        "gender": row["gender"],
                        "id": row["id"],
                        "orderId": row["orderId"],
                        "entryBy": row["entryBy"],
                        "phoneNumber": row["phone"],
                        "validFrom": row["validFrom"],
                        "validUntil": row["validUntil"],
                        "ticketId": row["ticketId"],
                        "verifiedAt": row["verifiedAt"],
                        "unverifiedAt": row["unverifiedAt"],
                        "ticket": {
                            "id": row["ticketId"],
                            "name": row["ticketName"],
                            "eventId": event_id,
                            "price": row["ticketPrice"],
                        },
                        "eventId": event_id,
                        "orderCreatedAt": row["orderCreatedAt"],
                        "orderUpdatedAt": row["orderUpdatedAt"],
                        "isScanned": bool(row["isVerified"]),
                        "hash": row["hash"],
                        "ticketCount": row["ticketCount"],
                        "ticketNum": row["ticketNum"],
                        "verifiedBy": {
                            "id": row["verifiedById"],
                            "name": row["verifiedByName"],
                        },
                        "isHide": False,
                        "genderRank": None,
                    }
                    for row in data
                ]

        # Siapkan respons
        response_data = {"tickets": formatted_data}
        if is_initial_sync:
            response_data["pagination"] = {
                "totalRecords": total_records,
                "totalPages": total_pages,
                "currentPage": page,
                "pageSize": page_size,
            }

        return {
            "status": "SUCCESS",
            "message": "Synchronization successful",
            "data": response_data,
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        response.status_code = 500
        return {"success": False, "error": str(e)}


class TicketVerificationUpdate(BaseModel):
    hash: str
    scanned_at: Optional[datetime]
    scanned_by: Optional[str]
    un_scanned_at: Optional[datetime]
    un_scanned_by: Optional[str]

class SyncPayload2(BaseModel):
    event_id: str
    last_sync_at: Optional[datetime]
    list_update_tickets: List[TicketVerificationUpdate]
# Update Sync Handler Code


@ticket.post('/api/sync-data')
async def synchronize_tickets(
    response: Response,
    body: SyncPayload2,
    # Parameter page dan page_size telah dihapus dari sini
    user: dict = Depends(get_current_user),
):
    try:
        event_id = body.event_id
        username = user["username"]
        local_tz = pytz.timezone("Asia/Makassar")
        now = datetime.now(local_tz)

        if 'eventId' in user and user['eventId'] != event_id:
            raise HTTPException(status_code=403, detail="User does not have access to this event.")

        async with online_engine.begin() as conn:
            # ... (Langkah 1 & 2 tidak ada perubahan) ...
            user_id_query = text("SELECT id FROM users WHERE username = :username LIMIT 1")
            result = await conn.execute(user_id_query, {"username": username})
            user_id = result.scalar_one_or_none()

            if not user_id:
                raise ValueError(f"User ID not found for username: {username}")

            if body.list_update_tickets:
                update_query = text("""
                    UPDATE ticket_verification
                    SET
                        scanned_at = :scanned_at,
                        scanned_by = :scanned_by,
                        un_scanned_at = :un_scanned_at,
                        un_scanned_by = :un_scanned_by
                    WHERE hash = :hash
                """)

                for ticket_update in body.list_update_tickets:
                    # Menghapus timezone info sebelum mengirim ke DB
                    scanned_at_naive = ticket_update.scanned_at.replace(tzinfo=None) if ticket_update.scanned_at else None
                    un_scanned_at_naive = ticket_update.un_scanned_at.replace(tzinfo=None) if ticket_update.un_scanned_at else None

                    await conn.execute(update_query, {
                        "hash": ticket_update.hash,
                        "scanned_at": scanned_at_naive, # Gunakan versi naive
                        "scanned_by": ticket_update.scanned_by,
                        "un_scanned_at": un_scanned_at_naive, # Gunakan versi naive
                        "un_scanned_by": ticket_update.un_scanned_by,
                    })
            # =================================================================
            # LANGKAH 3: AMBIL SEMUA ID TIKET YANG BERUBAH (TANPA PAGINASI)
            # =================================================================
            filter_query_base = """
                FROM orders o
                JOIN tickets t ON t.order_id = o.id
                JOIN transactions t2 ON t2.order_id = o.id
                JOIN ticket_categories tc ON tc.id = t.ticket_category_id
                JOIN ticket_verification tv ON tv.ticket_code = t.code
                WHERE t.event_id = :event_id AND o.order_status_id = 1
            """
            params = {"event_id": event_id}

            if body.last_sync_at:
                filter_query_base += " AND (o.date > :last_sync_at OR tv.scanned_at > :last_sync_at OR tv.un_scanned_at > :last_sync_at)"
                params["last_sync_at"] = body.last_sync_at

            excluded_hashes = [t.hash for t in body.list_update_tickets] if body.list_update_tickets else []
            if excluded_hashes:
                filter_query_base += " AND tv.hash != ALL(:excluded_hashes)"
                params["excluded_hashes"] = excluded_hashes

            # Logika untuk menghitung total records, offset, dan limit/offset clause telah dihapus.
            # Kueri sekarang mengambil semua ID tiket yang cocok.
            ids_query = text(f"SELECT t.id {filter_query_base} ORDER BY t2.created_at, t.customer_email")
            
            ids_result = await conn.execute(ids_query, params)
            ticket_ids = [row[0] for row in ids_result]

            # =================================================================
            # LANGKAH 4: AMBIL DATA LENGKAP (TIDAK ADA PERUBAHAN DI SINI)
            # =================================================================
            structured_data = {
                "orders": [], "tickets": [], "ticket_categories": [],
                "ticket_verifications": [], "ticket_custom_fields": [],
                "transactions": []
            }

            if ticket_ids:
                details_query = text("""
                    SELECT 
                        o.id AS o_id, o.date AS o_date, o.total_amount AS o_total_amount, o.admin_fees AS o_admin_fees, 
                        o.entry_by AS o_entry_by, o.order_status_id AS o_order_status_id, o.customer_id AS o_customer_id, 
                        o.payment_url AS o_payment_url, o.expired_date AS o_expired_date,
                        t.id AS t_id, t.code AS t_code, t.customer_email AS t_customer_email, t.customer_gender AS t_customer_gender, 
                        t.customer_name AS t_customer_name, t.event_id AS t_event_id, t.order_id AS t_order_id, 
                        t.ticket_category_id AS t_ticket_category_id, t.customer_phone_number AS t_customer_phone_number, t.price AS t_price,
                        tc.id AS tc_id, tc.maximum_tickets_per_transaction AS tc_maximum_tickets_per_transaction, tc.name AS tc_name, 
                        tc.price AS tc_price, tc.sales_end_time AS tc_sales_end_time, tc.sales_start_time AS tc_sales_start_time, 
                        tc.stock AS tc_stock, tc.terms_and_conditions AS tc_terms_and_conditions, tc.event_id AS tc_event_id, 
                        tc.ticket_category_status_id AS tc_ticket_category_status_id, tc.staff_only AS tc_staff_only, 
                        tc."position" AS tc_position, tc.valid_from AS tc_valid_from, tc.valid_until AS tc_valid_until,
                        tv.id AS tv_id, tv.hash AS tv_hash, tv.scan_device AS tv_scan_device, tv.scanned_at AS tv_scanned_at, 
                        tv.scanned_by AS tv_scanned_by, tv.ticket_code AS tv_ticket_code, tv.ticket_id AS tv_ticket_id, 
                        tv.un_scanned_at AS tv_un_scanned_at, tv.un_scanned_by AS tv_un_scanned_by,
                        t2.id AS t2_id, t2.amount AS t2_amount, t2.date AS t2_date, t2.order_id AS t2_order_id,
                        t2.source AS t2_source, t2.created_at AS t2_created_at, t2.updated_at AS t2_updated_at,
                        t2.payment_type AS t2_payment_type, t2.transaction_status_id AS t2_transaction_status_id,
                        tcf.id AS tcf_id, tcf.ticket_id AS tcf_ticket_id, tcf.name AS tcf_field_name, tcf.value AS tcf_field_value
                    FROM orders o
                    JOIN tickets t ON t.order_id = o.id
                    JOIN transactions t2 ON t2.order_id = o.id
                    JOIN ticket_categories tc ON tc.id = t.ticket_category_id
                    JOIN ticket_verification tv ON tv.ticket_code = t.code
                    LEFT JOIN ticket_custom_fields tcf ON tcf.ticket_id = t.id
                    WHERE t.id = ANY(:ticket_ids)
                """)

                details_params = {"ticket_ids": ticket_ids}
                result_proxy = await conn.execute(details_query, details_params)

                orders_map, tickets_map, ticket_categories_map, ticket_verifications_map, ticket_custom_fields_map, transactions_map = {}, {}, {}, {}, {}, {}

                for row in result_proxy.mappings():
                    # Kunci dictionary diubah agar memiliki prefiks, cocok dengan placeholder di klien
                    orders_map[row['o_id']] = {
                        "o_id": row['o_id'], "o_date": row['o_date'], "o_total_amount": row['o_total_amount'], 
                        "o_admin_fees": row['o_admin_fees'], "o_entry_by": row['o_entry_by'], 
                        "o_order_status_id": row['o_order_status_id'], "o_customer_id": row['o_customer_id'], 
                        "o_payment_url": row['o_payment_url'], "o_expired_date": row['o_expired_date']
                    }
                    
                    tickets_map[row['t_id']] = {
                        "t_id": row['t_id'], "t_code": row['t_code'], "t_customer_email": row['t_customer_email'], 
                        "t_customer_gender": row['t_customer_gender'], "t_customer_name": row['t_customer_name'], 
                        "t_event_id": row['t_event_id'], "t_order_id": row['t_order_id'], 
                        "t_ticket_category_id": row['t_ticket_category_id'], 
                        "t_customer_phone_number": row['t_customer_phone_number'], "t_price": row['t_price']
                    }
                    
                    ticket_categories_map[row['tc_id']] = {
                        "tc_id": row['tc_id'], "tc_maximum_tickets_per_transaction": row['tc_maximum_tickets_per_transaction'], 
                        "tc_name": row['tc_name'], "tc_price": row['tc_price'], "tc_sales_end_time": row['tc_sales_end_time'], 
                        "tc_sales_start_time": row['tc_sales_start_time'], "tc_stock": row['tc_stock'], 
                        "tc_terms_and_conditions": row['tc_terms_and_conditions'], "tc_event_id": row['tc_event_id'], 
                        "tc_ticket_category_status_id": row['tc_ticket_category_status_id'], 
                        "tc_staff_only": row['tc_staff_only'], "tc_position": row['tc_position'], 
                        "tc_valid_from": row['tc_valid_from'], "tc_valid_until": row['tc_valid_until']
                    }

                    ticket_verifications_map[row['tv_id']] = {
                        "tv_id": row['tv_id'], "tv_hash": row['tv_hash'], "tv_scan_device": row['tv_scan_device'], 
                        "tv_scanned_at": row['tv_scanned_at'], "tv_scanned_by": row['tv_scanned_by'], 
                        "tv_ticket_code": row['tv_ticket_code'], "tv_ticket_id": row['tv_ticket_id'], 
                        "tv_un_scanned_at": row['tv_un_scanned_at'], "tv_un_scanned_by": row['tv_un_scanned_by']
                    }

                    transactions_map[row['t2_id']] = {
                        "t2_id": row['t2_id'], "t2_amount": row['t2_amount'], "t2_date": row['t2_date'], 
                        "t2_order_id": row['t2_order_id'], "t2_source": row['t2_source'], 
                        "t2_created_at": row['t2_created_at'], "t2_updated_at": row['t2_updated_at'], 
                        "t2_payment_type": row['t2_payment_type'], "t2_transaction_status_id": row['t2_transaction_status_id']
                    }
                    
                    if row['tcf_id']:
                        ticket_custom_fields_map[row['tcf_id']] = {
                            "tcf_id": row['tcf_id'], "tcf_ticket_id": row['tcf_ticket_id'], 
                            "tcf_field_name": row['tcf_field_name'], "tcf_field_value": row['tcf_field_value']
                        }
                
                structured_data = {
                    "orders": list(orders_map.values()),
                    "tickets": list(tickets_map.values()),
                    "ticket_categories": list(ticket_categories_map.values()),
                    "ticket_verifications": list(ticket_verifications_map.values()),
                    "ticket_custom_fields": list(ticket_custom_fields_map.values()),
                    "transactions": list(transactions_map.values())
                }

                structured_data = {
                    "orders": list(orders_map.values()), "tickets": list(tickets_map.values()),
                    "ticket_categories": list(ticket_categories_map.values()), "ticket_verifications": list(ticket_verifications_map.values()),
                    "ticket_custom_fields": list(ticket_custom_fields_map.values()), "transactions": list(transactions_map.values())
                }

            # Siapkan respons dengan format baru
            response_data = {
                "last_sync_at": body.last_sync_at.isoformat() if body.last_sync_at else None,
                "current_sync_time": now.isoformat(),
                "data": structured_data
            }

            # Blok 'if is_initial_sync' yang menambahkan 'pagination' ke respons telah dihapus.
            
            return {
                "status": "SUCCESS",
                "message": "Synchronization successful",
                **response_data,
            }

    except Exception as e:
        import traceback
        traceback.print_exc()
        response.status_code = 500
        return {"success": False, "error": str(e)}

@ticket.get('/api/events/all')
async def read_orders5(
    search: Optional[str] = Query(None, description="Search by name or email"),
    ticket_type: Optional[str] = Query(
        None, description="Filter by ticket type"),
    verified: Optional[bool] = Query(
        None, description="Filter by verification status (true/false)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(
        50, ge=1, le=3000, description="Number of results per page"),
    offline: Optional[bool] = Query(
        None, description="Filter by offline online"),
    last_sync_at: Optional[datetime] = Query(
        None, description="Filter by last sync status (date time)"),
    user: dict = Depends(get_current_user),
):
    try:
        event_id = user["eventId"]
        offset = (page - 1) * page_size

        local_tz = pytz.timezone("Asia/Makassar")
        today_date_obj = datetime.now(local_tz).date()

        async with online_engine.begin() as conn:
            # === LANGKAH 1: Bangun semua filter dan jalankan kueri COUNT ===

            filter_query_base = """
                FROM orders o
                JOIN tickets t ON t.order_id = o.id
                left JOIN transactions t2 ON t2.order_id = o.id
                JOIN ticket_categories tc ON tc.id = t.ticket_category_id
                left JOIN ticket_verification tv ON tv.ticket_code = t.code
                WHERE t.event_id = :event_id
            """
            params = {'event_id': event_id, 'today_date': today_date_obj}

            filter_conditions = []

            if search:
                filter_conditions.append(
                    "(LOWER(t.customer_name) LIKE LOWER(:search) OR LOWER(t.customer_email) LIKE LOWER(:search))")
                params['search'] = f"%{search}%"
            if ticket_type:
                filter_conditions.append("tc.id = :ticket_type")
                params['ticket_type'] = ticket_type
            if offline is not None:
                filter_conditions.append(
                    "o.entry_by != 'anonymous'" if offline else "o.entry_by = 'anonymous'")
            if last_sync_at:
                filter_conditions.append(
                    "(t2.created_at > :last_sync_at OR tv.scanned_at > :last_sync_at OR tv.un_scanned_at > :last_sync_at)")
                params['last_sync_at'] = last_sync_at

            if verified is not None:
                is_verified_logic = """
                (CASE
                    WHEN tc.valid_from IS NOT NULL AND tc.valid_until IS NOT NULL AND CAST(tc.valid_until AS DATE) > CAST(tc.valid_from AS DATE) THEN
                        CASE
                            WHEN tv.scanned_at IS NOT NULL AND CAST(tv.scanned_at AS DATE) = CAST(:today_date AS DATE) THEN
                                CASE WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE ELSE TRUE END
                            ELSE FALSE
                        END
                    ELSE
                        CASE WHEN tv.scanned_at IS NULL THEN FALSE WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE ELSE TRUE END
                END)
                """
                filter_conditions.append(
                    f"{is_verified_logic} = {'TRUE' if verified else 'FALSE'}")

            if filter_conditions:
                filter_query_base += " AND " + " AND ".join(filter_conditions)

            count_query = text(
                f"SELECT COUNT(DISTINCT t.id) {filter_query_base}")
            count_result = await conn.execute(count_query, params)
            total_records = count_result.scalar_one()
            total_pages = (total_records + page_size - 1) // page_size

            if verified is False:
                order_by_clause = "ORDER BY t.customer_name"
            elif verified is True:
                order_by_clause = "ORDER BY tv.scanned_at DESC"
            else:
                order_by_clause = "ORDER BY t2.created_at, t.customer_email"

            ids_query = text(f"""
                SELECT t.id 
                {filter_query_base}
                {order_by_clause}
                LIMIT :page_size OFFSET :offset
            """)

            ids_params = params.copy()
            ids_params.update({'page_size': page_size, 'offset': offset})

            ids_result = await conn.execute(ids_query, ids_params)
            ticket_ids = [row[0] for row in ids_result]

            formatted_data = []
            if ticket_ids:
                final_order_map = {id: i for i, id in enumerate(ticket_ids)}

                details_query = text("""
                    WITH ticket_data AS (
                        SELECT 
                            o.id AS "id", t.id AS "orderId", tv.id AS "tvId", os.name AS "orderStatus",
                            tc.name AS "ticketName", tc.price AS "ticketPrice",
                            tc.valid_from AS "validFrom", tc.valid_until AS "validUntil",
                            t2.created_at AS "orderCreatedAt", u.address, tv.hash AS "hash",
                            o.entry_by AS "entryBy", u2.name AS "verifiedByName",
                            
                            CASE
                                WHEN tc.valid_from IS NOT NULL AND tc.valid_until IS NOT NULL AND CAST(tc.valid_until AS DATE) > CAST(tc.valid_from AS DATE) THEN
                                    CASE WHEN tv.scanned_at IS NOT NULL AND CAST(tv.scanned_at AS DATE) = CAST(:today_date AS DATE) THEN
                                        CASE WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE ELSE TRUE END
                                    ELSE FALSE END
                                ELSE
                                    CASE WHEN tv.scanned_at IS NULL THEN FALSE WHEN tv.un_scanned_at IS NOT NULL AND tv.un_scanned_at > tv.scanned_at THEN FALSE ELSE TRUE END
                            END AS "isVerified",
                            tv.scanned_at AS "verified_at", tv.un_scanned_at AS "unverifiedAt",
                            tv.scanned_by AS "verifiedById", tv.un_scanned_by AS "unverifiedBy",
                            ROW_NUMBER() OVER (PARTITION BY t.order_id ORDER BY t.id) AS "ticketNum",
                            COUNT(*) OVER (PARTITION BY t.order_id) AS "ticketCount",
                            t.customer_email AS "email", t.customer_name AS "name",
                            t.customer_gender AS "gender", t.customer_phone_number AS "phone",
                            tc.id AS "ticketId"
                        FROM orders o
                        Join order_statuses os on os.id = o.order_status_id
                        JOIN tickets t ON t.order_id = o.id
                        left JOIN transactions t2 ON t2.order_id = o.id  
                        left JOIN ticket_verification tv ON tv.ticket_code = t.code 
                        LEFT JOIN users u2 ON u2.id = tv.scanned_by
                        LEFT JOIN ticket_categories tc ON tc.id = t.ticket_category_id
                        LEFT JOIN users u ON u.email = o.customer_id 
                        LEFT JOIN ticket_custom_fields tcf ON tcf.ticket_id = t.id
                        WHERE t.id = ANY(:ticket_ids)
                        GROUP BY 
                            o.id, t.id, tv.id, o.order_status_id, tc.name, tc.price, t2.created_at, os.name, 
                            u.address, tv.hash, o.entry_by, u2.name, tv.scanned_at, tv.un_scanned_at,
                            tv.scanned_by, tv.un_scanned_by, t.customer_email, t.customer_name, 
                            t.customer_gender, t.customer_phone_number, tc.id, t.order_id,
                            tc.valid_from, tc.valid_until
                    )
                    SELECT * FROM ticket_data
                """)

                details_params = {'ticket_ids': ticket_ids,
                                'today_date': today_date_obj}
                result_proxy = await conn.execute(details_query, details_params)
                data = result_proxy.mappings().all()

                data.sort(key=lambda row: final_order_map.get(
                    row["orderId"], float('inf')))

                formatted_data = [
                    {
                        "address": "", "name": row["name"], "email": row["email"],
                        "gender": row["gender"], "id": row["id"], "orderId": row["orderId"],
                        "entryBy": row["entryBy"], "phoneNumber": row["phone"], "birthDate": "",
                        "citizenId": "", "tshirtSize": "", "validFrom": row["validFrom"],
                        "validUntil": row["validUntil"], "emergencyCallName": "",
                        "orderStatus": row["orderStatus"], "ticketId": row["ticketId"],
                        "verifiedAt": row["verified_at"],
                        "ticket": {
                            "id": row["ticketId"], "name": row["ticketName"], "eventId": event_id, "price": row["ticketPrice"]
                        },
                        "eventId": event_id, "orderCreatedAt": row["orderCreatedAt"],
                        "isScanned": bool(row["isVerified"]), "hash": row["hash"], "ticketCount": row["ticketCount"],
                        "ticketNum": row["ticketNum"],
                        "verifiedBy": {"id": row["verifiedById"], "name": row["verifiedByName"], },
                        "isHide": False, "genderRank": None
                    } for row in data
                ]

        return {
            "status": "SUCCESS", "message": "okay",
            "data": {
                "tickets": formatted_data,
                "pagination": {"totalRecords": total_records, "totalPages": total_pages, "currentPage": page, "pageSize": page_size},
            }
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=3000, reload=True)

