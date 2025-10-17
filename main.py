"""
API de Evaluación de Entropía de Contraseñas
FastAPI con arquitectura modular separada
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from models.models import (
    PasswordRequest,
    PasswordResponse,
    ErrorResponse
)
from services.services import evaluate_password
from database.database import init_database, close_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestiona el ciclo de vida de la aplicación (startup y shutdown)"""
    # Startup
    print("\n" + "="*60)
    print("🚀 Iniciando Password Entropy Evaluation API")
    print("="*60)
    
    if not init_database():
        print("\n❌ No se pudo iniciar la API")
        print("   Ejecuta primero: python migrate_csv_to_sqlite.py\n")
        raise RuntimeError("Base de datos no disponible")
    
    print("\n📚 Documentación Swagger disponible en: http://localhost:8000/docs")
    print("📚 Documentación ReDoc disponible en: http://localhost:8000/redoc")
    print("="*60 + "\n")
    
    yield
    
    # Shutdown
    close_database()


app = FastAPI(
    title="Password Entropy Evaluation API",
    description="""
    ## 🔐 API de Evaluación de Entropía de Contraseñas
    
    Esta API evalúa la fortaleza de contraseñas mediante el cálculo científico de entropía.
    
    ### 📐 Fórmula de Entropía
    ```
    E = L × log₂(N)
    ```
    
    Donde:
    - **E**: Entropía en bits
    - **L**: Longitud de la contraseña
    - **N**: Tamaño del alfabeto (keyspace)
    
    ### 📊 Clasificación de Fortaleza
    
    | Entropía (bits) | Clasificación |
    |-----------------|---------------|
    | 0 - 40          | Muy Débil     |
    | 40 - 60         | Débil         |
    | 60 - 80         | Aceptable     |
    | 80 - 100        | Fuerte        |
    | 100+            | Muy Fuerte    |
    
    ### 🎯 Características
    
    - ✅ Cálculo matemático de entropía
    - ✅ Validación contra 1 millón de contraseñas comunes
    - ✅ Estimación de tiempo de crackeo (10¹¹ intentos/segundo)
    - ✅ Análisis de composición de caracteres
    - ✅ Recomendaciones de seguridad personalizadas
    - ✅ Sin persistencia de contraseñas (Zero Storage)
    
    ### 🔒 Seguridad
    
    Esta API **NO almacena ni registra** las contraseñas enviadas.
    Todas las evaluaciones se realizan en memoria y se descartan inmediatamente.
    
    ### 📚 Proyecto Académico
    
    Desarrollado para la materia de **Seguridad de la Información**.
    Demuestra la implementación práctica de:
    - Cálculo de entropía (L, N, E)
    - Validación contra diccionarios
    - Análisis de tiempo de crackeo por fuerza bruta
    """,
    version="1.0.0",
    contact={
        "name": "Equipo de Desarrollo",
        "email": "seguridad@ejemplo.com",
    },
    license_info={
        "name": "MIT License",
    },
    lifespan=lifespan
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get(
    "/",
    summary="Información de la API",
    description="Devuelve información básica sobre la API y enlaces a la documentación"
)
async def root():
    """Endpoint raíz con información general de la API"""
    return {
        "name": "Password Entropy Evaluation API",
        "version": "1.0.0",
        "description": "API para evaluar la fortaleza de contraseñas mediante cálculo de entropía",
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json"
        },
        "endpoint": "/api/v1/password/evaluate (POST)",
        "features": [
            "Cálculo de entropía (E = L × log₂(N))",
            "Validación contra 1M de contraseñas comunes",
            "Estimación de tiempo de crackeo",
            "Análisis de composición",
            "Zero storage (no guarda contraseñas)"
        ]
    }

@app.post(
    "/api/v1/password/evaluate",
    response_model=PasswordResponse,
    responses={
        200: {
            "description": "Evaluación exitosa",
            "content": {
                "application/json": {
                    "example": {
                        "success": True,
                        "evaluation": {
                            "strength": "Fuerte",
                            "score": 4,
                            "entropy": 95.27,
                            "is_common": False,
                            "rank": None,
                            "crack_time": {
                                "value": 12345.67,
                                "unit": "años"
                            },
                            "composition": {
                                "length": 17,
                                "has_lowercase": True,
                                "has_uppercase": True,
                                "has_digits": True,
                                "has_symbols": True,
                                "keyspace": 94
                            },
                            "recommendation": "Buena contraseña. Mantenla segura y no la reutilices en otros sitios."
                        }
                    }
                }
            }
        },
        400: {
            "model": ErrorResponse,
            "description": "Solicitud inválida - Datos de entrada incorrectos"
        },
        500: {
            "model": ErrorResponse,
            "description": "Error interno del servidor"
        }
    },
    summary="Evaluar Contraseña",
    description="""
    Evalúa la fortaleza de una contraseña mediante un análisis completo:
    
    ### Proceso de Evaluación:
    
    1. **Cálculo de L (Longitud)**: Cuenta el número total de caracteres
    2. **Cálculo de N (Keyspace)**: Determina el tamaño del alfabeto según los tipos de caracteres usados:
       - Minúsculas (a-z): +26
       - Mayúsculas (A-Z): +26
       - Dígitos (0-9): +10
       - Símbolos: +32
    3. **Cálculo de Entropía**: Aplica la fórmula E = L × log₂(N)
    4. **Validación de Diccionario**: Busca la contraseña en 1 millón de contraseñas comunes
    5. **Penalización**: Si está en el diccionario, score = 0 y entropía = 0.0
    6. **Análisis de Composición**: Identifica tipos de caracteres presentes
    7. **Estimación de Crackeo**: Calcula tiempo usando 10¹¹ intentos/segundo
    8. **Recomendación**: Proporciona consejos personalizados de seguridad
    
    ### Clasificación de Fortaleza:
    
    - **0-40 bits**: Muy Débil
    - **40-60 bits**: Débil
    - **60-80 bits**: Aceptable
    - **80-100 bits**: Fuerte
    - **100+ bits**: Muy Fuerte
    
    ### ⚠️ Importante:
    
    Esta API **NO almacena ni registra** las contraseñas enviadas.
    Todas las evaluaciones se realizan en memoria y los datos se descartan inmediatamente.
    """,
    tags=["Evaluación"]
)
async def evaluate_password_endpoint(request: PasswordRequest):
    """
    Evalúa la fortaleza de una contraseña y devuelve un análisis completo.
    
    **Ejemplo de uso:**
    ```bash
    curl -X POST "http://localhost:8000/api/v1/password/evaluate" \\
      -H "Content-Type: application/json" \\
      -d '{"password":"MiContr@señ@2024!"}'
    ```
    """
    try:
        # Llamar al servicio de evaluación
        evaluation = evaluate_password(request.password)
        
        # Retornar respuesta exitosa
        return PasswordResponse(
            success=True,
            evaluation=evaluation
        )
        
    except Exception as e:
        # Log del error (en producción usar logging apropiado)
        print(f"Error al evaluar contraseña: {str(e)}")
        
        # Retornar error genérico sin exponer detalles internos
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno al evaluar la contraseña. Por favor, intenta de nuevo."
        )

# ============================================================================
# EJECUCIÓN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )