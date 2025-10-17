"""
Gestión de conexión y operaciones con la base de datos SQLite
"""

import sqlite3
import os
from typing import Optional
from functools import lru_cache

# ============================================================================
# CONFIGURACIÓN
# ============================================================================

DB_FILE = 'passwords.db'
DB_CONNECTION = None

# ============================================================================
# GESTIÓN DE CONEXIÓN
# ============================================================================

def get_db_connection() -> sqlite3.Connection:
    """
    Obtiene una conexión optimizada a SQLite
    
    Returns:
        sqlite3.Connection: Conexión a la base de datos
    """
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    # Optimizaciones para lectura
    conn.execute('PRAGMA journal_mode=WAL')  # Write-Ahead Logging
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA cache_size=10000')  # Cache de 10MB
    conn.execute('PRAGMA temp_store=MEMORY')
    return conn

def init_database() -> bool:
    """
    Inicializa la conexión a la base de datos
    
    Returns:
        bool: True si la inicialización fue exitosa, False en caso contrario
    """
    global DB_CONNECTION
    
    if not os.path.exists(DB_FILE):
        print(f"⚠️  Base de datos '{DB_FILE}' no encontrada.")
        print("   Ejecuta primero: python migrate_csv_to_sqlite.py")
        return False
    
    try:
        DB_CONNECTION = get_db_connection()
        cursor = DB_CONNECTION.cursor()
        cursor.execute("SELECT COUNT(*) FROM passwords")
        total = cursor.fetchone()[0]
        print(f"✅ Base de datos conectada: {total:,} contraseñas cargadas")
        return True
    except Exception as e:
        print(f"❌ Error al conectar con la base de datos: {e}")
        return False

def close_database() -> None:
    """Cierra la conexión a la base de datos"""
    global DB_CONNECTION
    if DB_CONNECTION:
        DB_CONNECTION.close()
        print("🔌 Conexión a base de datos cerrada")

# ============================================================================
# OPERACIONES DE CONSULTA
# ============================================================================

@lru_cache(maxsize=10000)
def is_common_password(password: str) -> bool:
    """
    Verifica si la contraseña está en el diccionario
    Usa cache LRU para mejorar rendimiento en búsquedas repetidas
    
    Args:
        password (str): Contraseña a verificar
    
    Returns:
        bool: True si la contraseña es común, False en caso contrario
    """
    if not DB_CONNECTION:
        return False
    
    try:
        cursor = DB_CONNECTION.cursor()
        cursor.execute(
            'SELECT 1 FROM passwords WHERE password_lower = ? LIMIT 1',
            (password.lower(),)
        )
        return cursor.fetchone() is not None
    except Exception as e:
        print(f"Error en búsqueda de contraseña: {e}")
        return False

def get_password_rank(password: str) -> Optional[int]:
    """
    Obtiene el ranking de una contraseña si existe en la base de datos
    
    Args:
        password (str): Contraseña a buscar
    
    Returns:
        Optional[int]: Rank de la contraseña o None si no existe
    """
    if not DB_CONNECTION:
        return None
    
    try:
        cursor = DB_CONNECTION.cursor()
        cursor.execute(
            'SELECT rank FROM passwords WHERE password_lower = ?',
            (password.lower(),)
        )
        result = cursor.fetchone()
        return result[0] if result else None
    except Exception as e:
        print(f"Error al obtener rank: {e}")
        return None

def get_cache_info() -> dict:
    """
    Obtiene información sobre el cache LRU
    
    Returns:
        dict: Estadísticas del cache
    """
    cache_info = is_common_password.cache_info()
    return {
        "hits": cache_info.hits,
        "misses": cache_info.misses,
        "size": cache_info.currsize,
        "maxsize": cache_info.maxsize
    }