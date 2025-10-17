"""
Servicios de lógica de negocio para evaluación de contraseñas
"""

import math
from models.models import PasswordEvaluation, CompositionInfo, CrackTime
from database.database import is_common_password, get_password_rank

# ============================================================================
# FUNCIONES DE CÁLCULO BÁSICAS
# ============================================================================

def calculate_L(password: str) -> int:
    """
    Calcula la longitud de la contraseña (L)
    
    Args:
        password (str): Contraseña a evaluar
    
    Returns:
        int: Longitud de la contraseña
    """
    return len(password)

def calculate_N(password: str) -> int:
    """
    Calcula el tamaño del alfabeto (keyspace) N
    
    El keyspace es la suma de todos los tipos de caracteres únicos posibles
    que se usaron para construir la contraseña.
    
    Args:
        password (str): Contraseña a evaluar
    
    Returns:
        int: Tamaño del alfabeto
    """
    keyspace = 0
    
    # Verificar presencia de diferentes tipos de caracteres
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() for c in password)
    
    # Sumar el tamaño de cada conjunto de caracteres utilizado
    if has_lowercase:
        keyspace += 26  # a-z
    if has_uppercase:
        keyspace += 26  # A-Z
    if has_digits:
        keyspace += 10  # 0-9
    if has_symbols:
        keyspace += 32  # Símbolos comunes
    
    return keyspace if keyspace > 0 else 1

def calculate_entropy(password: str) -> float:
    """
    Calcula la entropía de la contraseña usando la fórmula: E = L × log₂(N)
    
    Args:
        password (str): Contraseña a evaluar
    
    Returns:
        float: Entropía en bits (redondeado a 2 decimales)
    """
    L = calculate_L(password)
    N = calculate_N(password)
    
    if L == 0 or N == 0:
        return 0.0
    
    entropy = L * math.log2(N)
    return round(entropy, 2)

# ============================================================================
# ANÁLISIS DE COMPOSICIÓN
# ============================================================================

def analyze_composition(password: str) -> CompositionInfo:
    """
    Analiza la composición de caracteres de la contraseña
    
    Args:
        password (str): Contraseña a analizar
    
    Returns:
        CompositionInfo: Información detallada de la composición
    """
    return CompositionInfo(
        length=calculate_L(password),
        has_lowercase=any(c.islower() for c in password),
        has_uppercase=any(c.isupper() for c in password),
        has_digits=any(c.isdigit() for c in password),
        has_symbols=any(not c.isalnum() for c in password),
        keyspace=calculate_N(password)
    )

# ============================================================================
# CÁLCULO DE TIEMPO DE CRACKEO
# ============================================================================

def calculate_crack_time(entropy: float) -> CrackTime:
    """
    Calcula el tiempo estimado para crackear la contraseña por fuerza bruta
    Asume una tasa de ataque de 10¹¹ intentos/segundo
    
    Args:
        entropy (float): Entropía de la contraseña en bits
    
    Returns:
        CrackTime: Tiempo estimado en unidades legibles
    """
    attempts_per_second = 10**11  # 100 mil millones de intentos/segundo
    total_combinations = 2**entropy
    seconds = total_combinations / (2 * attempts_per_second)  # Dividido por 2 (promedio)
    
    # Convertir a unidades legibles
    if seconds < 1:
        return CrackTime(value=round(seconds * 1000, 2), unit="milisegundos")
    elif seconds < 60:
        return CrackTime(value=round(seconds, 2), unit="segundos")
    elif seconds < 3600:
        return CrackTime(value=round(seconds / 60, 2), unit="minutos")
    elif seconds < 86400:
        return CrackTime(value=round(seconds / 3600, 2), unit="horas")
    elif seconds < 31536000:
        return CrackTime(value=round(seconds / 86400, 2), unit="días")
    elif seconds < 31536000000:
        return CrackTime(value=round(seconds / 31536000, 2), unit="años")
    else:
        return CrackTime(value=round(seconds / 31536000000, 2), unit="milenios")

# ============================================================================
# EVALUACIÓN DE FORTALEZA
# ============================================================================

def get_strength_category(entropy: float) -> tuple[str, int, str]:
    """
    Determina la categoría de fortaleza basada en la entropía
    
    Args:
        entropy (float): Entropía en bits
    
    Returns:
        tuple: (strength, score, recommendation)
    """
    if entropy < 40:
        return (
            "Muy Débil",
            1,
            "Aumenta la longitud y usa diferentes tipos de caracteres (mayúsculas, minúsculas, números, símbolos)."
        )
    elif entropy < 60:
        return (
            "Débil",
            2,
            "Considera agregar más caracteres y variar los tipos de caracteres utilizados."
        )
    elif entropy < 80:
        return (
            "Aceptable",
            3,
            "Contraseña razonable, pero podría mejorarse con mayor longitud o complejidad."
        )
    elif entropy < 100:
        return (
            "Fuerte",
            4,
            "Buena contraseña. Mantenla segura y no la reutilices en otros sitios."
        )
    else:
        return (
            "Muy Fuerte",
            5,
            "Excelente contraseña. Asegúrate de almacenarla de forma segura."
        )

def evaluate_password(password: str) -> PasswordEvaluation:
    """
    Evalúa completamente la fortaleza de una contraseña
    
    Este es el servicio principal que:
    1. Calcula la entropía
    2. Verifica si está en el diccionario
    3. Analiza la composición
    4. Calcula el tiempo de crackeo
    5. Genera recomendaciones
    
    Args:
        password (str): Contraseña a evaluar
    
    Returns:
        PasswordEvaluation: Evaluación completa de la contraseña
    """
    # Calcular entropía
    entropy = calculate_entropy(password)
    
    # Verificar si está en el diccionario
    is_common = is_common_password(password)
    rank = get_password_rank(password) if is_common else None
    
    # Si está en el diccionario, penalizar severamente
    if is_common:
        strength = "Muy Débil (En Diccionario)"
        score = 0
        entropy_adjusted = 0.0
        recommendation = (
            f"Esta contraseña está en el puesto #{rank:,} de las más comunes. "
            "Es extremadamente predecible. Cámbiala inmediatamente."
        )
    else:
        # Obtener categoría basada en entropía
        strength, score, recommendation = get_strength_category(entropy)
        entropy_adjusted = entropy
    
    # Analizar composición
    composition = analyze_composition(password)
    
    # Calcular tiempo de crackeo
    crack_time = calculate_crack_time(entropy_adjusted)
    
    # Construir respuesta
    return PasswordEvaluation(
        strength=strength,
        score=score,
        entropy=entropy_adjusted,
        is_common=is_common,
        rank=rank,
        crack_time=crack_time,
        composition=composition,
        recommendation=recommendation
    )