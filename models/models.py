
from pydantic import BaseModel, Field
from typing import Optional, Dict

# ============================================================================
# MODELOS DE REQUEST
# ============================================================================

class PasswordRequest(BaseModel):
    """Modelo para la solicitud de evaluación de contraseña"""
    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Contraseña a evaluar",
        example="MiContr@señ@2024!"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "password": "MiContr@señ@2024!"
            }
        }

# ============================================================================
# MODELOS DE RESPONSE
# ============================================================================

class CompositionInfo(BaseModel):
    """Información sobre la composición de caracteres"""
    length: int = Field(..., description="Longitud de la contraseña")
    has_lowercase: bool = Field(..., description="Contiene minúsculas")
    has_uppercase: bool = Field(..., description="Contiene mayúsculas")
    has_digits: bool = Field(..., description="Contiene dígitos")
    has_symbols: bool = Field(..., description="Contiene símbolos")
    keyspace: int = Field(..., description="Tamaño del espacio de claves (alfabeto)")

class CrackTime(BaseModel):
    """Tiempo estimado de crackeo por fuerza bruta"""
    value: float = Field(..., description="Valor numérico del tiempo")
    unit: str = Field(..., description="Unidad de tiempo")

class PasswordEvaluation(BaseModel):
    """Resultado completo de la evaluación de contraseña"""
    strength: str = Field(..., description="Nivel de fortaleza de la contraseña")
    score: int = Field(..., ge=0, le=5, description="Puntuación de 0-5")
    entropy: float = Field(..., description="Entropía en bits")
    is_common: bool = Field(..., description="¿Está en el diccionario de contraseñas comunes?")
    rank: Optional[int] = Field(None, description="Ranking en el diccionario (si aplica)")
    crack_time: CrackTime = Field(..., description="Tiempo estimado de crackeo")
    composition: CompositionInfo = Field(..., description="Análisis de composición")
    recommendation: str = Field(..., description="Recomendación de seguridad")

class PasswordResponse(BaseModel):
    """Respuesta exitosa del endpoint de evaluación"""
    success: bool = Field(default=True)
    evaluation: PasswordEvaluation

class ErrorResponse(BaseModel):
    """Respuesta de error"""
    error: str = Field(..., description="Descripción del error")